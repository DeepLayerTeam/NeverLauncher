package repository

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestServerBridgeHAControlPlane01911MultiReplica(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	open := func() *SQLRepository {
		r, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
		if !ok {
			t.Fatal("repository is not SQLRepository")
		}
		return r
	}
	a, b := open(), open()
	defer a.db.Close()
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	projectID, nodeID := "ha01911-project", "ha01911-node"
	if _, err := a.SaveProject(model.Project{ID: projectID, Name: "HA 01911", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.ExecContext(ctx, `DELETE FROM server_bridge_control_commands_v3 WHERE server_id=$1`, nodeID)
	_, _ = a.db.ExecContext(ctx, `DELETE FROM server_bridge_nodes_v2 WHERE id=$1`, nodeID)
	node := model.ServerBridgeNode{ID: nodeID, Name: nodeID, Kind: "paper", ProjectID: projectID, KeyAlgorithm: "ed25519", PublicKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", KeyFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 3, CreatedAt: now}
	if _, err := a.SaveServerBridgeNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	runtimeID := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := a.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET runtime_id=$2,runtime_epoch=21,runtime_last_seen_at=$3 WHERE id=$1`, nodeID, runtimeID, now); err != nil {
		t.Fatal(err)
	}
	cmd := model.ServerBridgeControlCommand{ID: "ctl_ha01911", ServerID: nodeID, RuntimeEpoch: 21, RuntimeID: runtimeID, Type: "server.save", Payload: map[string]string{}, PayloadSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RequestedBy: "ha@example.test", IdempotencyKey: "ha01911-idem", Status: "pending", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}
	created, _, err := a.CreateServerBridgeControlCommand(ctx, cmd, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.DeliverySequence < 1 {
		t.Fatal("delivery sequence was not allocated")
	}

	type outcome struct {
		cmd model.ServerBridgeControlCommand
		err error
	}
	start := make(chan struct{})
	out := make(chan outcome, 2)
	var wg sync.WaitGroup
	contenders := []struct {
		r            *SQLRepository
		owner, token string
	}{{a, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "token_A_0123456789abcdef"}, {b, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "token_B_0123456789abcdef"}}
	for _, c := range contenders {
		wg.Add(1)
		go func(c struct {
			r            *SQLRepository
			owner, token string
		}) {
			defer wg.Done()
			<-start
			got, e := c.r.LeaseServerBridgeControlCommand(ctx, nodeID, 21, runtimeID, c.owner, c.token, 0, now, 30*time.Second)
			out <- outcome{got, e}
		}(c)
	}
	close(start)
	wg.Wait()
	close(out)
	var winner outcome
	wins, misses := 0, 0
	for r := range out {
		if r.err == nil {
			winner = r
			wins++
		} else if errors.Is(r.err, ErrNotFound) {
			misses++
		} else {
			t.Fatalf("unexpected lease error: %v", r.err)
		}
	}
	if wins != 1 || misses != 1 {
		t.Fatalf("expected one distributed owner, wins=%d misses=%d", wins, misses)
	}
	if winner.cmd.LeaseOwner == "" || winner.cmd.LeaseToken == "" {
		t.Fatal("winner was not fenced")
	}
	for name, replica := range map[string]*SQLRepository{"api-a": a, "api-b": b} {
		resumed, resumeErr := replica.LeaseServerBridgeControlCommand(ctx, nodeID, 21, runtimeID, winner.cmd.LeaseOwner, "ignored_new_token_0123456789", 0, now.Add(500*time.Millisecond), 30*time.Second)
		if resumeErr != nil || resumed.ID != winner.cmd.ID || resumed.LeaseToken != winner.cmd.LeaseToken || resumed.Attempt != winner.cmd.Attempt {
			t.Fatalf("%s did not resume the same durable lease: %+v err=%v", name, resumed, resumeErr)
		}
	}

	done, err := b.CompleteServerBridgeControlCommand(ctx, nodeID, 21, runtimeID, winner.cmd.ID, winner.cmd.LeaseOwner, winner.cmd.LeaseToken, winner.cmd.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(time.Second))
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("cross-replica completion: %+v err=%v", done, err)
	}
	replay, err := a.CompleteServerBridgeControlCommand(ctx, nodeID, 21, runtimeID, winner.cmd.ID, winner.cmd.LeaseOwner, winner.cmd.LeaseToken, winner.cmd.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(2*time.Second))
	if err != nil || replay.Status != "succeeded" {
		t.Fatalf("cross-replica idempotent ACK: %+v err=%v", replay, err)
	}
}

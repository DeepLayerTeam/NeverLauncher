package repository

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestServerBridgeHAControlPlane01911MultiReplica(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("LAUNCHER_SERVERBRIDGE_HA_DSN is not set")
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
	// A retried FAILED acknowledgement with an oversized reason must resolve
	// to the same normalized persisted response across backend replicas.
	failedCommand := cmd
	failedCommand.ID = "ctl_ha01911_long_failure"
	failedCommand.IdempotencyKey = "ha01911-idem-long-failure"
	createdFailed, _, createErr := a.CreateServerBridgeControlCommand(ctx, failedCommand, now)
	if createErr != nil || createdFailed.ID != failedCommand.ID {
		t.Fatalf("create long-failure command: %+v err=%v", createdFailed, createErr)
	}
	failedLease, leaseErr := b.LeaseServerBridgeControlCommand(ctx, nodeID, 21, runtimeID,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "longfailure_0123456789abcdef", created.DeliverySequence,
		now, 30*time.Second)
	if leaseErr != nil || failedLease.ID != failedCommand.ID {
		t.Fatalf("lease long-failure command: %+v err=%v", failedLease, leaseErr)
	}
	longFailure := "reason: " + strings.Repeat("x", 1500)
	failed, failedErr := a.CompleteServerBridgeControlCommand(ctx, nodeID, 21, runtimeID,
		failedLease.ID, failedLease.LeaseOwner, failedLease.LeaseToken,
		failedLease.DeliverySequence, "failed", map[string]string{"reason": "test"}, longFailure, now.Add(time.Second))
	if failedErr != nil || len(failed.Error) != 1024 || failed.Status != "failed" {
		t.Fatalf("persist normalized failure: %+v err=%v", failed, failedErr)
	}
	replayed, replayErr := b.CompleteServerBridgeControlCommand(ctx, nodeID, 21, runtimeID,
		failedLease.ID, failedLease.LeaseOwner, failedLease.LeaseToken,
		failedLease.DeliverySequence, "failed", map[string]string{"reason": "test"}, longFailure, now.Add(2*time.Second))
	if replayErr != nil || replayed.Error != failed.Error {
		t.Fatalf("idempotent failed acknowledgement across replicas: %+v err=%v", replayed, replayErr)
	}

	// Durable failover: a delivered external side effect with lost ACK cannot
	// be retried merely because its lease expired. Both API replicas must
	// observe the SAME indeterminate row, including its original lease fence.
	unknown := cmd
	unknown.ID = "ctl_ha01911_uncertain_0285"
	unknown.IdempotencyKey = "ha01911-uncertain-0285"
	unknown.CreatedAt, unknown.UpdatedAt = now, now
	_, _, err = a.CreateServerBridgeControlCommand(ctx, unknown, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.LeaseServerBridgeControlCommand(ctx, nodeID, 21, runtimeID,
		"cccccccccccccccccccccccccccccccc", "lease_uncertain_0123456789abcdef",
		failedLease.DeliverySequence, now, 5*time.Second)
	if err != nil || first.Status != "leased" {
		t.Fatalf("first uncertain lease: %+v %v", first, err)
	}
	_, err = b.LeaseServerBridgeControlCommand(ctx, nodeID, 21, runtimeID,
		"dddddddddddddddddddddddddddddddd", "lease_competing_0123456789abcdef",
		failedLease.DeliverySequence, now.Add(6*time.Second), 5*time.Second)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("redelivered uncertain command: %v", err)
	}
	for _, replica := range []*SQLRepository{a, b} {
		read, readErr := replica.GetServerBridgeControlCommand(ctx, nodeID, first.ID)
		if readErr != nil || read.Status != "indeterminate" || read.LeaseToken != first.LeaseToken || read.Attempt != 1 {
			t.Fatalf("cross-replica uncertain state: %+v %v", read, readErr)
		}
	}
	if _, err = b.CompleteServerBridgeControlCommand(ctx, nodeID, 21, runtimeID, first.ID, first.LeaseOwner, first.LeaseToken, first.DeliverySequence, "succeeded", nil, "", now.Add(7*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale result committed: %v", err)
	}
	// A pre-0.28.5 replica must be fenced by PostgreSQL itself, not just Go.
	if _, err = b.db.ExecContext(ctx, `UPDATE server_bridge_control_commands_v3 SET status='leased', lease_token='stale' WHERE id=$1`, first.ID); err == nil {
		t.Fatal("database trigger permitted old replica redelivery")
	}
}

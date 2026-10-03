package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Enabled in PostgreSQL CI with the same DSN as the ServerBridge HA suite.
func TestServerBridgeControl0195Postgres(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("repository is not SQLRepository")
	}
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	projectID := "control0195-project"
	if _, err := repo.SaveProject(model.Project{ID: projectID, Name: "Control 0195", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	_, _ = repo.db.ExecContext(ctx, `DELETE FROM server_bridge_nodes_v2 WHERE id='control0195-node'`)
	node := model.ServerBridgeNode{ID: "control0195-node", Name: "control0195-node", Kind: "paper", ProjectID: projectID, KeyAlgorithm: "ed25519", PublicKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", KeyFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 3, CreatedAt: now}
	if _, err := repo.SaveServerBridgeNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	runtimeID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := repo.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET runtime_id=$2,runtime_epoch=11,runtime_last_seen_at=$3 WHERE id=$1`, node.ID, runtimeID, now); err != nil {
		t.Fatal(err)
	}

	cmd := model.ServerBridgeControlCommand{
		ID: "ctl_control0195", ServerID: node.ID, RuntimeEpoch: 11, RuntimeID: runtimeID,
		Type: "server.save", Payload: map[string]string{},
		PayloadSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		RequestedBy:   "admin@example.test", IdempotencyKey: "control0195-idem", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	created, reused, err := repo.CreateServerBridgeControlCommand(ctx, cmd, now)
	if err != nil || reused || created.ID != cmd.ID {
		t.Fatalf("create: %+v reused=%v err=%v", created, reused, err)
	}
	replayed, reused, err := repo.CreateServerBridgeControlCommand(ctx, cmd, now.Add(time.Millisecond))
	if err != nil || !reused || replayed.ID != cmd.ID {
		t.Fatalf("idempotent create: %+v reused=%v err=%v", replayed, reused, err)
	}
	conflict := cmd
	conflict.ID = "ctl_control0195_conflict"
	conflict.RequestDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, _, err := repo.CreateServerBridgeControlCommand(ctx, conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	if _, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", now, 30*time.Second); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong runtime lease should conflict, got %v", err)
	}
	leased, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, now, 30*time.Second)
	if err != nil || leased.Status != "leased" || leased.Attempt != 1 {
		t.Fatalf("lease: %+v err=%v", leased, err)
	}
	done, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, "succeeded", map[string]string{"saved": "true"}, "", now.Add(time.Second))
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("complete: %+v err=%v", done, err)
	}
	done2, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, "succeeded", map[string]string{"saved": "true"}, "", now.Add(2*time.Second))
	if err != nil || done2.Status != "succeeded" {
		t.Fatalf("idempotent completion: %+v err=%v", done2, err)
	}
	if _, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, "succeeded", map[string]string{"saved": "false"}, "", now.Add(3*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-status ACK with conflicting result accepted: %v", err)
	}
	if _, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, "failed", nil, "late", now.Add(3*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting ACK accepted: %v", err)
	}
	var auditCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE id IN ($1,$2)`, "serverbridge-control-queued-"+cmd.ID, "serverbridge-control-complete-"+cmd.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("expected queued+completed transactional audit rows, got %d", auditCount)
	}
}

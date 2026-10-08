package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Включённый в PostgreSQL CI с одинаковый DSN как ServerBridge HA suite.
func TestServerBridgeEventStream0194Postgres(t *testing.T) {
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
	projectID := "events0194-project"
	if _, err := repo.SaveProject(model.Project{ID: projectID, Name: "Events 0194", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	_, _ = repo.db.ExecContext(ctx, `DELETE FROM server_bridge_nodes_v2 WHERE id='events0194-node'`)
	node := model.ServerBridgeNode{ID: "events0194-node", Name: "events0194-node", Kind: "paper", ProjectID: projectID, KeyAlgorithm: "ed25519", PublicKey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", KeyFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 3, CreatedAt: now}
	if _, err := repo.SaveServerBridgeNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	runtimeID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := repo.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET runtime_id=$2,runtime_epoch=9,runtime_last_seen_at=$3 WHERE id=$1`, node.ID, runtimeID, now); err != nil {
		t.Fatal(err)
	}

	events := []model.ServerBridgeEvent{
		{Sequence: 1, EventID: runtimeID + "-1", RuntimeID: runtimeID, Type: "server.startup", OccurredAtUnixMillis: now.UnixMilli(), Payload: map[string]string{"platform": "paper"}, PayloadSHA256: "1111111111111111111111111111111111111111111111111111111111111111", Signature: "sig1"},
		{Sequence: 2, EventID: runtimeID + "-2", RuntimeID: runtimeID, Type: "server.ready", OccurredAtUnixMillis: now.UnixMilli(), Payload: map[string]string{"platform": "paper"}, PayloadSHA256: "2222222222222222222222222222222222222222222222222222222222222222", Signature: "sig2"},
	}
	result, err := repo.AppendServerBridgeEvents(ctx, node.ID, 9, runtimeID, events, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.AckSequence != 2 || result.Inserted != 2 {
		t.Fatalf("unexpected append: %+v", result)
	}
	result, err = repo.AppendServerBridgeEvents(ctx, node.ID, 9, runtimeID, events, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result.AckSequence != 2 || result.Inserted != 0 {
		t.Fatalf("resend is not idempotent: %+v", result)
	}
	var auditCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE id IN ('serverbridge-event-events0194-node-9-1','serverbridge-event-events0194-node-9-2')`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("expected 2 transactional audit rows, got %d", auditCount)
	}

	conflict := events[1]
	conflict.PayloadSHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
	if _, err := repo.AppendServerBridgeEvents(ctx, node.ID, 9, runtimeID, []model.ServerBridgeEvent{conflict}, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected replay conflict, got %v", err)
	}
	gap := model.ServerBridgeEvent{Sequence: 4, EventID: runtimeID + "-4", RuntimeID: runtimeID, Type: "server.error", OccurredAtUnixMillis: now.UnixMilli(), Payload: map[string]string{}, PayloadSHA256: "4444444444444444444444444444444444444444444444444444444444444444", Signature: "sig4"}
	if _, err := repo.AppendServerBridgeEvents(ctx, node.ID, 9, runtimeID, []model.ServerBridgeEvent{gap}, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected gap conflict, got %v", err)
	}
}

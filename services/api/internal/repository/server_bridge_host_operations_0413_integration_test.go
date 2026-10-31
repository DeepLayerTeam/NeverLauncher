package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestHostOperationsPostgres0413(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	project := "host0413-project"
	server := "host0413-node"
	if _, err := a.SaveProject(model.Project{ID: project, Name: "Host operations 0413", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.ExecContext(ctx, `DELETE FROM server_bridge_host_operations_0413 WHERE server_id=$1`, server)
	_, _ = a.db.ExecContext(ctx, `DELETE FROM server_bridge_nodes_v2 WHERE id=$1`, server)
	node := model.ServerBridgeNode{ID: server, Name: server, Kind: "paper", ProjectID: project, KeyAlgorithm: "ed25519", PublicKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", KeyFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 3, CreatedAt: now}
	if _, err := a.SaveServerBridgeNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = a.db.ExecContext(context.Background(), `DELETE FROM server_bridge_host_operations_0413 WHERE server_id=$1`, server)
		_, _ = a.db.ExecContext(context.Background(), `DELETE FROM server_bridge_nodes_v2 WHERE id=$1`, server)
	}()
	op := HostOperation0413{ID: "host0413-id-1", ServerID: server, Action: "restart", RequestedBy: "operator", IdempotencyKey: "idem-host-0413-0001", RequestDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RemoteNodeID: "host-node-1", BaselineRuntimeID: "runtime-old", HostBefore: json.RawMessage(`{"nodeId":"host-node-1"}`)}
	created, replay, err := a.CreateHostOperation0413(ctx, op)
	if err != nil || replay || created.State != "indeterminate" {
		t.Fatalf("intent %+v replay=%t err=%v", created, replay, err)
	}
	byKey, keyErr := b.GetHostOperationByKey0413(ctx, server, op.IdempotencyKey)
	if keyErr != nil || byKey.ID != created.ID {
		t.Fatalf("lookup by key %+v %v", byKey, keyErr)
	}
	op.ID = "another-id"
	again, replay, err := b.CreateHostOperation0413(ctx, op)
	if err != nil || !replay || again.ID != created.ID {
		t.Fatalf("replay %+v replay=%t err=%v", again, replay, err)
	}
	op.Action = "stop"
	if _, _, err = b.CreateHostOperation0413(ctx, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("digest conflict: %v", err)
	}
	op.Action = "restart"
	op.IdempotencyKey = "different-idem-key-0413"
	op.RequestDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, err = b.CreateHostOperation0413(ctx, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("concurrent unknown host operation should conflict: %v", err)
	}
	created.State = "accepted"
	created.RemoteReceipt = json.RawMessage(`{"action":"restart","state":"succeeded"}`)
	accepted, err := a.FinishHostOperation0413(ctx, created, "indeterminate")
	if err != nil || accepted.State != "accepted" {
		t.Fatalf("accepted %+v %v", accepted, err)
	}
	accepted.State = "succeeded"
	accepted.HostAfter = json.RawMessage(`{"nodeId":"host-node-1","status":{"observedStatus":"running"}}`)
	succeeded, err := b.FinishHostOperation0413(ctx, accepted, "accepted")
	if err != nil || succeeded.State != "succeeded" {
		t.Fatalf("verified %+v %v", succeeded, err)
	}
	if _, err = a.FinishHostOperation0413(ctx, accepted, "accepted"); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal result overwritten %v", err)
	}
}

package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// A topology read includes *all* registered proxy/backend pairs, including
// legacy and just-registered nodes without a signed routing snapshot. Such
// pairs must be marked stale, not fail with a SQL NULL -> time.Time scan error.
func TestServerBridgeTopologyWithoutRoutingSnapshot0215(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("expected PostgreSQL repository")
	}
	defer r.db.Close()
	if _, err := r.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	projectID := fmt.Sprintf("topology-nullability-%d", time.Now().UnixNano())
	if _, err := r.SaveProject(model.Project{ID: projectID, Name: "Topology NULL regression", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ids := []string{projectID + "-proxy", projectID + "-paper"}
	for i, kind := range []string{"velocity", "paper"} {
		node := model.ServerBridgeNode{
			ID: ids[i], Name: ids[i], Kind: kind, ProjectID: projectID,
			KeyAlgorithm: "ed25519", PublicKey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
			KeyFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			IdentityEpoch:  1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 2, CreatedAt: now,
		}
		if _, err := r.SaveServerBridgeNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM server_bridge_nodes_v2 WHERE id=$1 OR id=$2`, ids[0], ids[1])
	})
	// One node has a heartbeat, but neither has a routing snapshot. This
	// deliberately exercises both nullable timestamp fallback paths.
	if err := r.TouchServerBridgeNodeHeartbeat(ctx, ids[0], "velocity", "0.21.5", 2, now); err != nil {
		t.Fatal(err)
	}
	edges, err := r.ListServerBridgeTopology(ctx)
	if err != nil {
		t.Fatalf("topology read of legacy nodes failed: %v", err)
	}
	for _, edge := range edges {
		if edge.SourceNodeID != ids[0] || edge.TargetNodeID != ids[1] {
			continue
		}
		if edge.Status != "source-stale" {
			t.Fatalf("legacy routing must fail closed, got %q", edge.Status)
		}
		if edge.LastSeenAt.IsZero() || edge.CreatedAt.IsZero() {
			t.Fatalf("topology timestamps must be non-NULL: %+v", edge)
		}
		return
	}
	t.Fatalf("expected legacy topology edge for %s -> %s", ids[0], ids[1])
}

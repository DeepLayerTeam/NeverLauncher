package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// This executes real PostgreSQL route selection and the optimistic admission
// mutation; a source-only test cannot prove SQL behavior. CI must supply a DSN.
func TestNetworkAdmissionPostgreSQL0288(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("LAUNCHER_SERVERBRIDGE_HA_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	r, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("expected PostgreSQL")
	}
	defer r.db.Close()
	if _, err := r.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("network-policy-%d", time.Now().UnixNano())
	if _, err := r.SaveProject(model.Project{ID: project, Name: "Network capacity integration", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	source, target := project+"-velocity", project+"-paper"
	t.Cleanup(func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM server_bridge_nodes_v2 WHERE id=$1 OR id=$2`, source, target)
	})
	now := time.Now().UTC()
	runtime := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, it := range []struct{ id, kind string }{{source, "velocity"}, {target, "paper"}} {
		node := model.ServerBridgeNode{ID: it.id, Name: it.id, Kind: it.kind, ProjectID: project, KeyAlgorithm: "ed25519",
			PublicKey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", KeyFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 3, CreatedAt: now}
		if _, err := r.SaveServerBridgeNode(ctx, node); err != nil {
			t.Fatal(err)
		}
		// Repository-level fixture representing an already verified signed
		// heartbeat: cryptographic ingress verification has separate tests.
		_, err := r.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET runtime_id=$2,runtime_epoch=1,routing_state='ready',routing_health='healthy',routing_accepting=true,routing_players_online=2,routing_capacity_max=15,routing_revision=1,routing_observed_at=$3,last_heartbeat_at=$3,routing_digest=$2,routing_signature='synthetic-test-only' WHERE id=$1`, it.id, runtime, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	routes, err := r.ListServerBridgeAllowedBackends(ctx, source, now)
	if err != nil || len(routes) != 1 || routes[0].NodeID != target {
		t.Fatalf("initial route: %+v %v", routes, err)
	}
	zero := 0
	rev, err := r.SetServerBridgeNetworkCapacity(ctx, target, project, runtime, 1, 0, &zero, "integration-test", now)
	if err != nil || rev != 1 {
		t.Fatalf("deny policy: rev=%d err=%v", rev, err)
	}
	if _, err := r.SetServerBridgeNetworkCapacity(ctx, target, project, runtime, 1, 0, &zero, "stale", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale optimistic policy accepted: %v", err)
	}
	if err := r.EnsureServerBridgeNodeRoutable(ctx, target, 1, runtime, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("closed target routable: %v", err)
	}
	routes, err = r.ListServerBridgeAllowedBackends(ctx, source, now)
	if err != nil || len(routes) != 0 {
		t.Fatalf("closed target selected: %+v %v", routes, err)
	}
	states, err := r.ListServerBridgeNetworkStates(ctx, project, now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range states {
		if s.NodeID == target {
			found = true
			if s.Routable || s.Reason != "operator-capacity-zero" || s.OperatorCapacityMax == nil || *s.OperatorCapacityMax != 0 {
				t.Fatalf("wrong network state: %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("missing target network state")
	}
	edges, err := r.ListServerBridgeTopology(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var edgeFound bool
	for _, e := range edges {
		if e.SourceNodeID == source && e.TargetNodeID == target {
			edgeFound = true
			if e.Status != "operator-capacity-full" {
				t.Fatalf("wrong topology status: %s", e.Status)
			}
		}
	}
	if !edgeFound {
		t.Fatal("topology edge missing")
	}
	five := 5
	rev, err = r.SetServerBridgeNetworkCapacity(ctx, target, project, runtime, 1, 1, &five, "integration-test", now)
	if err != nil || rev != 2 {
		t.Fatalf("restore policy: rev=%d err=%v", rev, err)
	}
	if err := r.EnsureServerBridgeNodeRoutable(ctx, target, 1, runtime, now); err != nil {
		t.Fatalf("restored target not routable: %v", err)
	}
	routes, err = r.ListServerBridgeAllowedBackends(ctx, source, now)
	if err != nil || len(routes) != 1 || routes[0].CapacityMax != 5 {
		t.Fatalf("wrong effective cap: %+v %v", routes, err)
	}
}

package repository

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// TestServerBridgeHA0149 exercises two independent SQLRepository handles against
// one PostgreSQL database. CI enables it with NEVERLAUNCHER_SERVERBRIDGE_HA_DSN.
func TestServerBridgeHA0149(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r1, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("repo1 is not SQLRepository")
	}
	r2, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("repo2 is not SQLRepository")
	}
	defer r1.db.Close()
	defer r2.db.Close()
	if _, err := r1.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	projectID := "ha0149-project"
	if _, err := r1.SaveProject(model.Project{ID: projectID, Name: "HA 0149", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	_, _ = r1.db.ExecContext(ctx, `DELETE FROM server_bridge_nodes_v2 WHERE id='ha0149-node'`)
	node := model.ServerBridgeNode{ID: "ha0149-node", Name: "ha0149-node", Kind: "paper", ProjectID: projectID, ProfileID: "", KeyAlgorithm: "ed25519", PublicKey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", KeyFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 2, CreatedAt: now}
	if _, err := r1.SaveServerBridgeNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := r1.TouchServerBridgeNodeHeartbeat(ctx, node.ID, node.Kind, "0.14.9", now); err != nil {
		t.Fatal(err)
	}

	// Both API replicas race the same signed-request nonce. PostgreSQL PK +
	// identity epoch condition must allow exactly one consumer.
	nonceHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	for _, repo := range []*SQLRepository{r1, r2} {
		go func(repo *SQLRepository) {
			defer wg.Done()
			accepted, err := repo.ConsumeServerBridgeNodeNonce(ctx, node.ID, nonceHash, 1, now, now.Add(3*time.Minute))
			results <- accepted
			errs <- err
		}(repo)
	}
	wg.Wait()
	close(results)
	close(errs)
	accepted := 0
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for v := range results {
		if v {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("expected exactly one nonce consumer, got %d", accepted)
	}

	// Seed an expired nonce; HA maintenance must clear it without touching the
	// valid one and the shared status snapshot must observe zero expired backlog.
	_, err := r1.db.ExecContext(ctx, `INSERT INTO server_bridge_node_nonces_v2(node_id,nonce_hash,identity_epoch,consumed_at,expires_at) VALUES($1,$2,1,$3,$4) ON CONFLICT DO NOTHING`, node.ID, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", now.Add(-4*time.Minute), now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r1.MaintainServerBridge(ctx, now); err != nil {
		t.Fatal(err)
	}
	status, err := r2.ServerBridgeHAStatus(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.ExpiredNonceBacklog != 0 {
		t.Fatalf("expired nonce backlog=%d", status.ExpiredNonceBacklog)
	}
	if status.NodesFresh < 1 {
		t.Fatalf("expected fresh ServerBridge node: %+v", status)
	}
}

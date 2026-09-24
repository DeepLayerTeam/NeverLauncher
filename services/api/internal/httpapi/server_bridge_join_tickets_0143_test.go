package httpapi

import (
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestOneTimeJoinTicket0143CSPRNGIdentifier(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 128; i++ {
		id, err := newServerBridgeJoinTicketID0143()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "jt_") || len(id) < 32 {
			t.Fatalf("unexpected ticket id shape: %q", id)
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate CSPRNG ticket id: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestOneTimeJoinTicket0143BindsIdentityAndConsumesExactlyOnce(t *testing.T) {
	now := time.Now().UTC()
	fingerprint := strings.Repeat("a", 64)
	store := &serverBridgeStore{
		servers: map[string]bridgeServerRecord{
			"paper-0143": {ID: "paper-0143", Status: "active", IdentityEpoch: 7, KeyFingerprint: fingerprint},
		},
		joins: map[string]bridgeJoinRecord{},
	}
	join := bridgeJoinRecord{
		ID: "jt_test", TicketVersion: 2, Username: "TicketPlayer", ServerID: "paper-0143",
		IssuedIdentityEpoch: 7, IssuedKeyFingerprint: fingerprint,
		Status: "active", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	store.joins[store.joinKey(join.Username, join.ServerID)] = join

	wrong := model.ServerBridgeJoinRedemption{NodeID: "paper-0143", IdentityEpoch: 8, KeyFingerprint: fingerprint, NonceHash: strings.Repeat("1", 64)}
	if _, ok := store.consumeJoinV2(join, wrong); ok {
		t.Fatal("ticket accepted a different node identity epoch")
	}

	proofs := []model.ServerBridgeJoinRedemption{
		{NodeID: "paper-0143", IdentityEpoch: 7, KeyFingerprint: fingerprint, NonceHash: strings.Repeat("2", 64), RemoteIP: "192.0.2.10"},
		{NodeID: "paper-0143", IdentityEpoch: 7, KeyFingerprint: fingerprint, NonceHash: strings.Repeat("3", 64), RemoteIP: "192.0.2.11"},
	}
	var wg sync.WaitGroup
	results := make(chan bool, len(proofs))
	for _, proof := range proofs {
		proof := proof
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok := store.consumeJoinV2(join, proof)
			results <- ok
		}()
	}
	wg.Wait()
	close(results)

	allowed := 0
	for ok := range results {
		if ok {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("expected exactly one ticket redemption, got %d", allowed)
	}
	stored := store.joins[store.joinKey(join.Username, join.ServerID)]
	if stored.Status != "consumed" || stored.ConsumedAt.IsZero() || stored.RedeemedIdentityEpoch != 7 || stored.RedeemedKeyFingerprint != fingerprint || len(stored.RedeemedNonceHash) != 64 {
		t.Fatalf("redemption audit proof was not persisted: %+v", stored)
	}
}

package sqlitecore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

func joinFixture(t *testing.T) (*Repository, *Auth, string, ed25519.PrivateKey, JoinGrant, Tokens) {
	t.Helper()
	r, a, path, password := setupAuth(t)
	ctx := context.Background()
	project(t, r)
	profile(t, r)
	if _, e := r.SaveChannel(ctx, model.ReleaseChannel{ID: "stable", ProjectID: "project", Name: "stable"}, "owner"); e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.RegisterNode(ctx, NodeRegistration{ID: "node1", ProjectID: "project", ProfileID: "vanilla", Channel: "stable", PublicKeyHex: hex.EncodeToString(pub), Actor: "owner"}); e != nil {
		t.Fatal(e)
	}
	_, e = a.SaveMinecraftIdentity(ctx, model.MinecraftProfile{UserID: "owner", UUID: "123e4567-e89b-42d3-a456-426614174000", Name: "Player_1"}, "owner")
	if e != nil {
		t.Fatal(e)
	}
	tokens, e := a.LoginLocal(ctx, "owner@never.test", password, "", "test-launcher")
	if e != nil {
		t.Fatal(e)
	}
	_, mc, e := a.IssueMinecraftSession(ctx, tokens.AccessToken, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := a.IssueJoinTicket(ctx, tokens.AccessToken, mc, "node1")
	if e != nil {
		t.Fatal(e)
	}
	return r, a, path, priv, grant, tokens
}
func signJoinProof(t *testing.T, priv ed25519.PrivateKey, action string, epoch int64, payload []byte) NodeProof {
	t.Helper()
	nonce := make([]byte, 24)
	if _, e := rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	p := NodeProof{NodeID: "node1", IdentityEpoch: epoch, Timestamp: time.Now().UTC().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
	p.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(CanonicalNodeRequest(action, p, SignedPayloadHash(payload)))))
	return p
}
func TestJoinAtomicRaceCrashRestartAndReplay(t *testing.T) {
	r, _, path, priv, grant, _ := joinFixture(t)
	ctx := context.Background()
	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proof := signJoinProof(t, priv, "redeem", 1, []byte(grant.Ticket))
			if _, e := r.RedeemJoinTicket(ctx, grant.Ticket, proof, "127.0.0.1"); e == nil {
				winners.Add(1)
			} else if !errors.Is(e, ErrJoinRejected) {
				t.Errorf("race: %v", e)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("one-time redemption winners=%d", winners.Load())
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e := OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	state, e := r.TicketStatus(ctx, grant.Ticket)
	if e != nil || state != "consumed" {
		t.Fatalf("after restart state=%q error=%v", state, e)
	}
	p := signJoinProof(t, priv, "redeem", 1, []byte(grant.Ticket))
	if _, e = r.RedeemJoinTicket(ctx, grant.Ticket, p, ""); !errors.Is(e, ErrJoinRejected) {
		t.Fatalf("reused after restart: %v", e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestNodeNonceReplaySignatureAndTamper(t *testing.T) {
	r, _, _, priv, _, _ := joinFixture(t)
	ctx := context.Background()
	p := signJoinProof(t, priv, "ping", 1, []byte("request"))
	if e := r.ConsumeSignedNonce(ctx, p, []byte("request")); e != nil {
		t.Fatal(e)
	}
	if e := r.ConsumeSignedNonce(ctx, p, []byte("request")); !errors.Is(e, ErrReplay) {
		t.Fatalf("duplicate nonce accepted: %v", e)
	}
	p = signJoinProof(t, priv, "ping", 1, []byte("request"))
	if e := r.ConsumeSignedNonce(ctx, p, []byte("tampered")); !errors.Is(e, ErrNodeProof) {
		t.Fatalf("modified body accepted: %v", e)
	}
	p = signJoinProof(t, priv, "ping", 1, []byte("request"))
	p.Timestamp -= 600
	if e := r.ConsumeSignedNonce(ctx, p, []byte("request")); !errors.Is(e, ErrNodeProof) {
		t.Fatalf("stale timestamp accepted: %v", e)
	}
}
func TestJoinReplacementRotationRevocation(t *testing.T) {
	r, a, _, priv, first, tokens := joinFixture(t)
	ctx := context.Background()
	// A second issuance replaces the first without leaving two valid tickets.
	_, newerMC, e := a.IssueMinecraftSession(ctx, tokens.AccessToken, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	second, e := a.IssueJoinTicket(ctx, tokens.AccessToken, newerMC, "node1")
	if e != nil {
		t.Fatal(e)
	}
	status, e := r.TicketStatus(ctx, first.Ticket)
	if e != nil || status != "replaced" {
		t.Fatalf("first ticket not replaced: %q %v", status, e)
	}
	// Key rotation invalidates outstanding tickets, changes the signing epoch.
	pub2, priv2, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	node, e := r.RegisterNode(ctx, NodeRegistration{ID: "node1", ProjectID: "project", ProfileID: "vanilla", Channel: "stable", PublicKeyHex: hex.EncodeToString(pub2), Actor: "owner"})
	if e != nil || node.IdentityEpoch != 2 {
		t.Fatalf("rotation %v %+v", e, node)
	}
	p := signJoinProof(t, priv, "redeem", 1, []byte(first.Ticket))
	if _, e = r.RedeemJoinTicket(ctx, first.Ticket, p, ""); !errors.Is(e, ErrNodeProof) {
		t.Fatalf("old key accepted: %v", e)
	}
	p = signJoinProof(t, priv2, "redeem", 2, []byte(second.Ticket))
	if _, e = r.RedeemJoinTicket(ctx, second.Ticket, p, ""); !errors.Is(e, ErrJoinRejected) {
		t.Fatalf("invalidated ticket accepted: %v", e)
	}
	if e = a.RevokeSession(ctx, "owner", tokens.SessionID, "security"); e != nil {
		t.Fatal(e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestJoinUpgrade323PreservesUsers(t *testing.T) {
	r, _, path, _, _, _ := joinFixture(t)
	ctx := context.Background()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	store, e := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	e = store.Write(ctx, func(q sqlitedurable.Executor) error {
		for _, stmt := range []string{"DROP TABLE durable_job_attempts", "DROP TABLE durable_jobs", "DROP TABLE durable_outbox", "DROP TABLE durable_scope_leases", "DROP TABLE bridge_join_tickets", "DROP TRIGGER bridge_nonces_no_update", "DROP INDEX bridge_nonces_expiry", "DROP TABLE bridge_nonces", "DROP TABLE bridge_nodes", "PRAGMA user_version=323"} {
			if _, e := q.ExecContext(ctx, stmt); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
	u, e := r.GetUser(ctx, "owner")
	if e != nil || u.ID != "owner" {
		t.Fatalf("migration dropped user: %+v %v", u, e)
	}
	counts, e := r.Count(ctx)
	if e != nil || counts["bridge_nodes"] != 0 {
		t.Fatalf("wrong migration: %v %v", counts, e)
	}
}

func TestReplayNonceRemainsSpentAfterReopen(t *testing.T) {
	r, _, path, priv, _, _ := joinFixture(t)
	ctx := context.Background()
	proof := signJoinProof(t, priv, "ping", 1, []byte("persisted-request"))
	if err := r.ConsumeSignedNonce(ctx, proof, []byte("persisted-request")); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConsumeSignedNonce(ctx, proof, []byte("persisted-request")); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce replay after SQLite restart: %v", err)
	}
}

func TestRevokedAuthenticationRejectsPendingTicket(t *testing.T) {
	r, auth, _, priv, grant, tokens := joinFixture(t)
	ctx := context.Background()
	if err := auth.RevokeSession(ctx, "owner", tokens.SessionID, "logout"); err != nil {
		t.Fatal(err)
	}
	proof := signJoinProof(t, priv, "redeem", 1, []byte(grant.Ticket))
	if _, err := r.RedeemJoinTicket(ctx, grant.Ticket, proof, "127.0.0.1"); !errors.Is(err, ErrJoinRejected) {
		t.Fatalf("revoked session was accepted: %v", err)
	}
	if _, err := r.RedeemJoinTicket(ctx, grant.Ticket, proof, "127.0.0.1"); !errors.Is(err, ErrReplay) {
		t.Fatalf("failed redemption did not persist consumed nonce: %v", err)
	}
}

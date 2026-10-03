package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestServerBridgeControlValidation0195(t *testing.T) {
	if _, err := validateServerBridgeControlRequest0195("player.kick", map[string]string{"username": "Steve", "reason": "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := validateServerBridgeControlRequest0195("server.console", map[string]string{"command": "/save-all flush"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/", "stop", "op Steve", "say ok\nstop"} {
		if _, err := validateServerBridgeControlRequest0195("server.console", map[string]string{"command": bad}); err == nil {
			t.Fatalf("unsafe/non-allowlisted console command accepted: %q", bad)
		}
	}
	if _, err := validateServerBridgeControlRequest0195("server.shell", map[string]string{"command": "id"}); err == nil {
		t.Fatal("shell control type must not exist")
	}
}

func TestServerBridgeControlSignature0195(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := canonicalControlPayload0195(map[string]string{"message": "hello"})
	sum := sha256.Sum256(payload)
	canonical := serverBridgeControlCanonical0195("paper-main", "ctl_test", "abc123", "message.broadcast", hex.EncodeToString(sum[:]), 7, 2, 1000, 2000)
	signature := ed25519.Sign(priv, []byte(canonical))
	if !ed25519.Verify(pub, []byte(canonical), signature) {
		t.Fatal("valid control signature rejected")
	}
	if ed25519.Verify(pub, []byte(canonical+"tampered"), signature) {
		t.Fatal("tampered control signature accepted")
	}
	if len(base64.RawURLEncoding.EncodeToString(signature)) != 86 {
		t.Fatal("unexpected Ed25519 encoding")
	}
}

func TestServerBridgeControlMemoryIdempotencyLeaseAndAck0195(t *testing.T) {
	runtimeID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{}, controlIdempotency: map[string]string{}}
	now := time.Now().UTC()
	cmd := model.ServerBridgeControlCommand{ID: "ctl_one", ServerID: "paper-main", RuntimeEpoch: 9, RuntimeID: runtimeID, Type: "server.save", Payload: map[string]string{}, PayloadSHA256: "abc", RequestDigest: "request-1", RequestedBy: "admin@example.test", IdempotencyKey: "idem-12345678", Status: "pending", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Minute)}
	first, reused, err := store.createControl0195(cmd, now)
	if err != nil || reused || first.ID != cmd.ID {
		t.Fatalf("create: %+v reused=%v err=%v", first, reused, err)
	}
	replay, reused, err := store.createControl0195(cmd, now)
	if err != nil || !reused || replay.ID != cmd.ID {
		t.Fatalf("idempotent replay: %+v reused=%v err=%v", replay, reused, err)
	}
	conflict := cmd
	conflict.ID = "ctl_two"
	conflict.RequestDigest = "request-2"
	if _, _, err := store.createControl0195(conflict, now); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	leased, err := store.leaseControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, now, 30*time.Second)
	if err != nil || leased.Attempt != 1 || leased.Status != "leased" {
		t.Fatalf("lease: %+v err=%v", leased, err)
	}
	if _, err := store.leaseControl0195(cmd.ServerID, cmd.RuntimeEpoch, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now, 30*time.Second); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("wrong runtime must not receive command: %v", err)
	}
	done, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, "succeeded", map[string]string{"saved": "true"}, "", now.Add(time.Second))
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("complete: %+v err=%v", done, err)
	}
	again, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, "succeeded", map[string]string{"saved": "true"}, "", now.Add(2*time.Second))
	if err != nil || again.Status != "succeeded" {
		t.Fatalf("idempotent ACK failed: %+v err=%v", again, err)
	}
	if _, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, "succeeded", map[string]string{"saved": "false"}, "", now.Add(3*time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("same-status ACK with conflicting result accepted: %v", err)
	}
	if _, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, "failed", nil, "late conflict", now.Add(3*time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("conflicting ACK accepted: %v", err)
	}
}

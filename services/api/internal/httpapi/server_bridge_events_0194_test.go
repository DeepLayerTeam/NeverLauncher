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

func signedEvent0194(t *testing.T, private ed25519.PrivateKey, serverID, runtimeID string, sequence int64, eventType string, payload map[string]string) bridgeEventContract0194 {
	t.Helper()
	now := time.Now().UTC().UnixMilli()
	eventID := runtimeID + "-" + fmtInt0194(sequence)
	payloadBytes, err := canonicalBridgeEventPayload0194(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payloadBytes)
	digestHex := hex.EncodeToString(digest[:])
	canonical := bridgeEventCanonical0194(serverID, eventID, runtimeID, sequence, eventType, now, digestHex)
	return bridgeEventContract0194{
		Sequence: sequence, EventID: eventID, RuntimeID: runtimeID, Type: eventType,
		OccurredAtUnixMillis: now, Payload: payload, PayloadSHA256: digestHex,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(canonical))),
	}
}

func fmtInt0194(v int64) string {
	if v == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestServerBridgeEventSignature0194(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtime := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw := signedEvent0194(t, private, "paper-0194", runtime, 1, "server.ready", map[string]string{"platform": "paper"})
	event, err := validateBridgeEvent0194("paper-0194", runtime, "", raw, public, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	if event.Sequence != 1 || event.Type != "server.ready" {
		t.Fatalf("unexpected event: %+v", event)
	}

	raw.Payload["platform"] = "tampered"
	if _, err := validateBridgeEvent0194("paper-0194", runtime, "", raw, public, time.Now().UTC(), false); err == nil {
		t.Fatal("tampered event payload must fail digest/signature validation")
	}
}

func TestServerBridgeEventMemoryAckReplay0194(t *testing.T) {
	runtime := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	store := &serverBridgeStore{servers: map[string]bridgeServerRecord{
		"paper-0194": {ID: "paper-0194", Status: "active", RuntimeID: runtime, RuntimeEpoch: 7},
	}}
	server := store.servers["paper-0194"]
	events := []model.ServerBridgeEvent{
		{Sequence: 1, EventID: runtime + "-1", RuntimeID: runtime, Type: "server.startup", OccurredAtUnixMillis: time.Now().UnixMilli(), Payload: map[string]string{}, PayloadSHA256: "1111111111111111111111111111111111111111111111111111111111111111", Signature: "x"},
		{Sequence: 2, EventID: runtime + "-2", RuntimeID: runtime, Type: "server.ready", OccurredAtUnixMillis: time.Now().UnixMilli(), Payload: map[string]string{}, PayloadSHA256: "2222222222222222222222222222222222222222222222222222222222222222", Signature: "x"},
	}
	result, err := store.appendEvents0194(server, events, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if result.AckSequence != 2 || result.Inserted != 2 {
		t.Fatalf("unexpected first ACK: %+v", result)
	}

	result, err = store.appendEvents0194(server, events, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if result.AckSequence != 2 || result.Inserted != 0 {
		t.Fatalf("resend must be idempotent: %+v", result)
	}

	conflict := events[1]
	conflict.PayloadSHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
	if _, err := store.appendEvents0194(server, []model.ServerBridgeEvent{conflict}, time.Now().UTC()); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("conflicting replay must fail with ErrConflict: %v", err)
	}
	gap := model.ServerBridgeEvent{Sequence: 4, EventID: runtime + "-4", RuntimeID: runtime, Type: "server.ready", OccurredAtUnixMillis: time.Now().UnixMilli(), Payload: map[string]string{}, PayloadSHA256: "4444444444444444444444444444444444444444444444444444444444444444", Signature: "x"}
	if _, err := store.appendEvents0194(server, []model.ServerBridgeEvent{gap}, time.Now().UTC()); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("sequence gap must fail with ErrConflict: %v", err)
	}
}

func TestServerBridgeEventTypes0194(t *testing.T) {
	for _, required := range []string{"server.startup", "server.ready", "server.shutdown", "player.login", "player.join", "player.quit", "player.kick", "world.load", "world.unload", "proxy.connect", "proxy.switch", "server.crash", "server.error"} {
		if _, ok := serverBridgeEventTypes0194[required]; !ok {
			t.Fatalf("missing event type %s", required)
		}
	}
}

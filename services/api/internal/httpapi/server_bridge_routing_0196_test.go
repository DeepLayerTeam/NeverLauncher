package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func signedRouting0196(t *testing.T, serverID, runtimeID string, identity testBridgeNodeIdentity0142, state, health string, accepting bool, players, capacity int) bridgeRoutingV3Contract0196 {
	t.Helper()
	r := bridgeRoutingV3Contract0196{
		RuntimeID: runtimeID, ObservedAtUnixMillis: time.Now().UTC().UnixMilli(), State: state,
		AcceptingConnections: accepting, PlayersOnline: players, CapacityMax: capacity, Health: health,
	}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.PrivateKey, []byte(bridgeRoutingCanonical0196(serverID, r))))
	return r
}

func TestServerBridgeRouting0196NodeAttestationAndAdmission(t *testing.T) {
	identity := newTestBridgeNodeIdentity0142(t)
	runtimeID := strings.Repeat("a", 64)
	server := bridgeServerRecord{ID: "paper-routing-0196", Kind: "paper", Status: "active", PublicKey: identity.Encoded, KeyFingerprint: identity.Fingerprint, RuntimeID: runtimeID, RuntimeEpoch: 7}
	runtime := model.ServerBridgeRuntimeIdentity{RuntimeID: runtimeID}

	raw := signedRouting0196(t, server.ID, runtimeID, identity, "ready", "healthy", true, 12, 100)
	verified, err := validateAndVerifyBridgeRouting0196(server, &raw, runtime, time.Now().UTC())
	if err != nil {
		t.Fatalf("valid routing proof rejected: %v", err)
	}
	if verified.State != "ready" || verified.Health != "healthy" || !verified.AcceptingConnections || verified.Digest == "" {
		t.Fatalf("verified routing mismatch: %+v", verified)
	}

	tampered := raw
	tampered.Health = "unhealthy"
	if _, err := validateAndVerifyBridgeRouting0196(server, &tampered, runtime, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "accepting_inconsistent") {
		t.Fatalf("tampered/inconsistent routing accepted: %v", err)
	}

	full := signedRouting0196(t, server.ID, runtimeID, identity, "ready", "healthy", true, 100, 100)
	if _, err := validateAndVerifyBridgeRouting0196(server, &full, runtime, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "accepting_inconsistent") {
		t.Fatalf("full backend advertised as accepting: %v", err)
	}

	draining := signedRouting0196(t, server.ID, runtimeID, identity, "draining", "healthy", false, 12, 100)
	if _, err := validateAndVerifyBridgeRouting0196(server, &draining, runtime, time.Now().UTC()); err != nil {
		t.Fatalf("valid draining snapshot rejected: %v", err)
	}
}

func TestServerBridgeRouting0196FeatureAdvertised(t *testing.T) {
	features := bridgeFeatureFlags0191(serverBridgeV3Features0191)
	if !features[serverBridgeFeatureRoutingV2] {
		t.Fatalf("%s is not advertised by Protocol v3", serverBridgeFeatureRoutingV2)
	}
}

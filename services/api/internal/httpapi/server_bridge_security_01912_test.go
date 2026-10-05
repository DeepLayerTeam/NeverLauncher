package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func TestServerBridgeSecurityCapabilityDigest01912(t *testing.T) {
	const expected = "088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4"
	if got := serverBridgeExpectedSecurityCapabilityDigest01912(); got != expected {
		t.Fatalf("capability digest drift: got %s want %s", got, expected)
	}
	downgraded := append([]string(nil), serverBridgeSecurityRequiredFeatures01912[:len(serverBridgeSecurityRequiredFeatures01912)-1]...)
	if serverBridgeSecurityCapabilityDigest01912(downgraded) == expected {
		t.Fatal("capability downgrade preserved certified digest")
	}
}

func TestServerBridgeProtocolV3NodeCanonicalRejectsTamper01912(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fpRaw := sha256.Sum256(pub)
	fp := hex.EncodeToString(fpRaw[:])
	body := []byte(`{"protocolVersion":3,"serverId":"node-01912"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/node-01912/heartbeat?probe=1", strings.NewReader(string(body)))
	canonical := serverBridgeNodeRequestCanonical01912(req, body, "node-01912", fp, "1770000000", "nonce-01912", strings.Repeat("a", 64), serverBridgeExpectedSecurityCapabilityDigest01912())
	sig := ed25519.Sign(priv, []byte(canonical))
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("valid node signature rejected")
	}

	for name, mutated := range map[string]string{
		"runtime":     serverBridgeNodeRequestCanonical01912(req, body, "node-01912", fp, "1770000000", "nonce-01912", strings.Repeat("b", 64), serverBridgeExpectedSecurityCapabilityDigest01912()),
		"capability":  serverBridgeNodeRequestCanonical01912(req, body, "node-01912", fp, "1770000000", "nonce-01912", strings.Repeat("a", 64), strings.Repeat("0", 64)),
		"fingerprint": serverBridgeNodeRequestCanonical01912(req, body, "node-01912", strings.Repeat("f", 64), "1770000000", "nonce-01912", strings.Repeat("a", 64), serverBridgeExpectedSecurityCapabilityDigest01912()),
		"body":        serverBridgeNodeRequestCanonical01912(req, append(body, ' '), "node-01912", fp, "1770000000", "nonce-01912", strings.Repeat("a", 64), serverBridgeExpectedSecurityCapabilityDigest01912()),
	} {
		if ed25519.Verify(pub, []byte(mutated), sig) {
			t.Fatalf("tampered node %s retained valid signature", name)
		}
	}
}

func TestServerBridgeProtocolV3EventRejectsTamper01912(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fpRaw := sha256.Sum256(pub)
	fp := hex.EncodeToString(fpRaw[:])
	runtime := strings.Repeat("c", 64)
	payload := map[string]string{"platform": "paper"}
	payloadBytes, _ := canonicalBridgeEventPayload0194(payload)
	digestRaw := sha256.Sum256(payloadBytes)
	digest := hex.EncodeToString(digestRaw[:])
	now := time.Now().UTC().UnixMilli()
	raw := bridgeEventContract0194{Sequence: 1, EventID: runtime + "-1", RuntimeID: runtime, Type: "server.ready", OccurredAtUnixMillis: now, Payload: payload, PayloadSHA256: digest, SecurityProfile: serverBridgeSecurityProfile01912, CapabilityDigest: serverBridgeExpectedSecurityCapabilityDigest01912(), NodeKeyFingerprint: fp}
	canonical := serverBridgeEventCanonical01912("paper-01912", raw.EventID, runtime, fp, raw.CapabilityDigest, raw.Sequence, raw.Type, raw.OccurredAtUnixMillis, digest)
	raw.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(canonical)))
	if _, err := validateBridgeEvent0194("paper-01912", runtime, fp, raw, pub, time.Now().UTC(), true); err != nil {
		t.Fatal(err)
	}

	tampered := raw
	tampered.CapabilityDigest = strings.Repeat("0", 64)
	if _, err := validateBridgeEvent0194("paper-01912", runtime, fp, tampered, pub, time.Now().UTC(), true); err == nil {
		t.Fatal("tampered v3 event capability binding accepted")
	}
	tampered = raw
	tampered.RuntimeID = strings.Repeat("d", 64)
	if _, err := validateBridgeEvent0194("paper-01912", runtime, fp, tampered, pub, time.Now().UTC(), true); err == nil {
		t.Fatal("tampered v3 event runtime binding accepted")
	}
}

func TestServerBridgeProtocolV3CommandCanonicalRejectsReplayAcrossRuntime01912(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fpRaw := sha256.Sum256(pub)
	fp := hex.EncodeToString(fpRaw[:])
	canonical := serverBridgeControlCanonical01912("paper-01912", "cmd-1", strings.Repeat("e", 64), "server.save", strings.Repeat("1", 64), "channel", "lease", serverBridgeExpectedSecurityCapabilityDigest01912(), fp, 4, 8, 10, 1, 1000, 2000)
	sig := ed25519.Sign(priv, []byte(canonical))
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("valid command signature rejected")
	}
	replayed := serverBridgeControlCanonical01912("paper-01912", "cmd-1", strings.Repeat("f", 64), "server.save", strings.Repeat("1", 64), "channel", "lease", serverBridgeExpectedSecurityCapabilityDigest01912(), fp, 4, 9, 10, 1, 1000, 2000)
	if ed25519.Verify(pub, []byte(replayed), sig) {
		t.Fatal("command replay across runtime remained valid")
	}
}

func TestServerBridge3AllowlistRejectsTamperedBridge01912(t *testing.T) {
	paperHash := strings.Repeat("2", 64)
	features := `"security.protocol-v3-signing-domain","security.capability-downgrade-protection","security.command-signatures-v3","security.event-signatures-v3","security.runtime-instance-binding-v3","security.online-key-rotation-v1"`
	allowlist := `{"schemaVersion":"3.0","release":"ServerBridge 3","protocolVersion":3,"minimumProtocolVersion":3,"securityProfile":"serverbridge3-security-01912","securityCapabilityDigest":"` + serverBridgeExpectedSecurityCapabilityDigest01912() + `","requiredFeatures":[` + features + `],"releases":{"0.19.12":{"velocitySha256":["` + strings.Repeat("1", 64) + `"],"paperSha256":["` + paperHash + `"],"purpurSha256":["` + strings.Repeat("3", 64) + `"]}}}`
	srv := Server{Version: "0.19.12", Config: config.Config{Environment: "test", BridgeReleaseAllowlistJSON: allowlist}}
	server := bridgeServerRecord{ID: "paper-security-01912", Kind: "paper"}
	if decision := srv.validateBridgePluginMeasurement0135(server, "paper", "0.19.12", paperHash); !decision.Allowed || decision.Reason != "bridge_integrity_verified" {
		t.Fatalf("certified bridge rejected: %+v", decision)
	}
	if decision := srv.validateBridgePluginMeasurement0135(server, "paper", "0.19.12", strings.Repeat("f", 64)); decision.Allowed || decision.Reason != "bridge_integrity_hash_rejected" {
		t.Fatalf("tampered bridge accepted: %+v", decision)
	}
}

func TestServerBridgeSecurityFeatureSetIsExact01912(t *testing.T) {
	if !serverBridgeSecurityFeaturesExact01912(serverBridgeSecurityRequiredFeatures01912) {
		t.Fatal("certified security feature set rejected")
	}
	extra := append(append([]string(nil), serverBridgeSecurityRequiredFeatures01912...), "security.unapproved")
	if serverBridgeSecurityFeaturesExact01912(extra) {
		t.Fatal("security allowlist accepted uncertified extra feature")
	}
	duplicate := append([]string(nil), serverBridgeSecurityRequiredFeatures01912...)
	duplicate[len(duplicate)-1] = duplicate[0]
	if serverBridgeSecurityFeaturesExact01912(duplicate) {
		t.Fatal("security allowlist accepted duplicate/missing feature set")
	}
}

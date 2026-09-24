package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testBridgeNodeIdentity0142 struct {
	PublicKey   ed25519.PublicKey
	PrivateKey  ed25519.PrivateKey
	Encoded     string
	Fingerprint string
}

func newTestBridgeNodeIdentity0142(t *testing.T) testBridgeNodeIdentity0142 {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	return testBridgeNodeIdentity0142{
		PublicKey:   pub,
		PrivateKey:  priv,
		Encoded:     base64.RawURLEncoding.EncodeToString(pub),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

func registerTestBridgeNode0142(t *testing.T, h http.Handler, adminToken, id, name, kind, projectID, profileID string, identity testBridgeNodeIdentity0142) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id": id, "name": name, "kind": kind, "projectId": projectID, "profileId": profileID,
		"keyAlgorithm": "ed25519", "publicKey": identity.Encoded,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/register", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	return out
}

func signBridgeNodeRequest0142(t *testing.T, req *http.Request, nodeID string, identity testBridgeNodeIdentity0142) {
	t.Helper()
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	signBridgeNodeRequestWith0142(t, req, nodeID, identity, strconv.FormatInt(time.Now().UTC().Unix(), 10), base64.RawURLEncoding.EncodeToString(nonceBytes))
}

func signBridgeNodeRequestWith0142(t *testing.T, req *http.Request, nodeID string, identity testBridgeNodeIdentity0142, timestamp, nonce string) {
	t.Helper()
	var body []byte
	var err error
	if req.Body != nil {
		body, err = io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		req.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	canonical := serverBridgeCanonicalRequest0142(req, body, nodeID, timestamp, nonce)
	sig := ed25519.Sign(identity.PrivateKey, []byte(canonical))
	req.Header.Set(nodeIDHeader0142, nodeID)
	req.Header.Set(nodeFingerprintHeader0142, identity.Fingerprint)
	req.Header.Set(nodeTimestampHeader0142, timestamp)
	req.Header.Set(nodeNonceHeader0142, nonce)
	req.Header.Set(nodeSignatureHeader0142, base64.RawURLEncoding.EncodeToString(sig))
}

func TestServerBridgeNodeIdentity0142RejectsSignatureReplayAndStaleTimestamp(t *testing.T) {
	h := testServer(t)
	admin := loginAdmin(t, h)
	identity := newTestBridgeNodeIdentity0142(t)
	if rv := registerTestBridgeNode0142(t, h, admin, "crypto-0142", "Crypto 0142", "paper", "demo-project", "vanilla", identity); rv.Code != http.StatusCreated {
		t.Fatalf("register=%d %s", rv.Code, rv.Body.String())
	}

	body := `{"protocolVersion":2,"serverType":"paper","pluginVersion":"0.14.2","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	first := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-0142/heartbeat", strings.NewReader(body))
	first.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequestWith0142(t, first, "crypto-0142", identity, ts, nonce)
	firstOut := httptest.NewRecorder()
	h.ServeHTTP(firstOut, first)
	// testServer has no bridge allowlist, so a valid cryptographic request reaches
	// the ordinary heartbeat policy regardless of its eventual policy status.
	if firstOut.Code == http.StatusUnauthorized || firstOut.Code == http.StatusConflict {
		t.Fatalf("valid signed heartbeat rejected at identity boundary: %d %s", firstOut.Code, firstOut.Body.String())
	}

	replay := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-0142/heartbeat", strings.NewReader(body))
	replay.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequestWith0142(t, replay, "crypto-0142", identity, ts, nonce)
	replayOut := httptest.NewRecorder()
	h.ServeHTTP(replayOut, replay)
	if replayOut.Code != http.StatusConflict || !strings.Contains(replayOut.Body.String(), "serverbridge_node_nonce_replayed") {
		t.Fatalf("signed request replay accepted: %d %s", replayOut.Code, replayOut.Body.String())
	}

	staleNonce := make([]byte, 24)
	if _, err := rand.Read(staleNonce); err != nil {
		t.Fatal(err)
	}
	stale := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-0142/heartbeat", strings.NewReader(body))
	stale.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequestWith0142(t, stale, "crypto-0142", identity, strconv.FormatInt(time.Now().Add(-5*time.Minute).Unix(), 10), base64.RawURLEncoding.EncodeToString(staleNonce))
	staleOut := httptest.NewRecorder()
	h.ServeHTTP(staleOut, stale)
	if staleOut.Code != http.StatusUnauthorized || !strings.Contains(staleOut.Body.String(), "serverbridge_node_timestamp_out_of_window") {
		t.Fatalf("stale signed request accepted: %d %s", staleOut.Code, staleOut.Body.String())
	}
}

func TestServerBridgeNodeIdentity0142RejectsBodyTamperAndRetiredKey(t *testing.T) {
	h := testServer(t)
	admin := loginAdmin(t, h)
	admin, _ = registerTestPasskey117(t, h, admin)
	firstIdentity := newTestBridgeNodeIdentity0142(t)
	if rv := registerTestBridgeNode0142(t, h, admin, "crypto-rotate-0142", "Crypto Rotate 0142", "paper", "demo-project", "vanilla", firstIdentity); rv.Code != http.StatusCreated {
		t.Fatalf("register=%d %s", rv.Code, rv.Body.String())
	}

	originalBody := `{"protocolVersion":2,"serverType":"paper","pluginVersion":"0.14.2","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	tampered := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-rotate-0142/heartbeat", strings.NewReader(originalBody))
	tampered.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, tampered, "crypto-rotate-0142", firstIdentity)
	// Change the exact bytes after signing. The authenticated body hash must bind
	// the request before JSON parsing or policy evaluation.
	tampered.Body = io.NopCloser(strings.NewReader(strings.Replace(originalBody, "0.14.2", "0.14.2-tampered", 1)))
	tamperedOut := httptest.NewRecorder()
	h.ServeHTTP(tamperedOut, tampered)
	if tamperedOut.Code != http.StatusUnauthorized || !strings.Contains(tamperedOut.Body.String(), "serverbridge_node_signature_invalid") {
		t.Fatalf("tampered signed body accepted: %d %s", tamperedOut.Code, tamperedOut.Body.String())
	}

	wrongFingerprint := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-rotate-0142/heartbeat", strings.NewReader(originalBody))
	wrongFingerprint.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, wrongFingerprint, "crypto-rotate-0142", firstIdentity)
	wrongFingerprint.Header.Set(nodeFingerprintHeader0142, strings.Repeat("0", 64))
	wrongFingerprintOut := httptest.NewRecorder()
	h.ServeHTTP(wrongFingerprintOut, wrongFingerprint)
	if wrongFingerprintOut.Code != http.StatusUnauthorized || !strings.Contains(wrongFingerprintOut.Body.String(), "serverbridge_node_fingerprint_mismatch") {
		t.Fatalf("wrong node fingerprint accepted: %d %s", wrongFingerprintOut.Code, wrongFingerprintOut.Body.String())
	}

	secondIdentity := newTestBridgeNodeIdentity0142(t)
	duplicateID := registerTestBridgeNode0142(t, h, admin, "crypto-rotate-0142", "Duplicate Crypto Rotate 0142", "paper", "demo-project", "vanilla", secondIdentity)
	if duplicateID.Code != http.StatusBadRequest || !strings.Contains(duplicateID.Body.String(), "rotate-identity") {
		t.Fatalf("existing node identity was replaceable through registration: %d %s", duplicateID.Code, duplicateID.Body.String())
	}

	rotateBody, err := json.Marshal(map[string]any{"keyAlgorithm": "ed25519", "publicKey": secondIdentity.Encoded})
	if err != nil {
		t.Fatal(err)
	}
	rotate := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-rotate-0142/rotate-identity", strings.NewReader(string(rotateBody)))
	rotate.Header.Set("Authorization", "Bearer "+admin)
	rotate.Header.Set("Content-Type", "application/json")
	rotateOut := httptest.NewRecorder()
	h.ServeHTTP(rotateOut, rotate)
	if rotateOut.Code != http.StatusOK || !strings.Contains(rotateOut.Body.String(), `"identityEpoch":2`) {
		t.Fatalf("identity rotation failed: %d %s", rotateOut.Code, rotateOut.Body.String())
	}

	retired := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-rotate-0142/heartbeat", strings.NewReader(originalBody))
	retired.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, retired, "crypto-rotate-0142", firstIdentity)
	retiredOut := httptest.NewRecorder()
	h.ServeHTTP(retiredOut, retired)
	if retiredOut.Code != http.StatusUnauthorized || !strings.Contains(retiredOut.Body.String(), "serverbridge_node_fingerprint_mismatch") {
		t.Fatalf("retired node key remained usable: %d %s", retiredOut.Code, retiredOut.Body.String())
	}

	current := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/crypto-rotate-0142/heartbeat", strings.NewReader(originalBody))
	current.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, current, "crypto-rotate-0142", secondIdentity)
	currentOut := httptest.NewRecorder()
	h.ServeHTTP(currentOut, current)
	if currentOut.Code == http.StatusUnauthorized || currentOut.Code == http.StatusConflict {
		t.Fatalf("rotated node identity rejected at auth boundary: %d %s", currentOut.Code, currentOut.Body.String())
	}

	duplicate := registerTestBridgeNode0142(t, h, admin, "crypto-duplicate-0142", "Crypto Duplicate 0142", "velocity", "demo-project", "vanilla", secondIdentity)
	if duplicate.Code != http.StatusBadRequest || !strings.Contains(duplicate.Body.String(), "public key") {
		t.Fatalf("duplicate node public key accepted: %d %s", duplicate.Code, duplicate.Body.String())
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureBridge02812(t *testing.T, backend string) (string, bridgeVerification02812, bridgeEnrollmentRequest0199) {
	t.Helper()
	root := t.TempDir()
	writeMarkerJar0199(t, filepath.Join(root, "paper.jar"), "io/papermc/paper/configuration/GlobalConfiguration.class")
	release := t.TempDir()
	writeCertifiedArtifact0199(t, release, "paper", "0.19.9")
	if err := provisionServerBridge0199([]string{"install", "--server-root", root, "--artifact-dir", release, "--bridge-version", "0.19.9", "--backend", backend, "--server-id", "paper-prod", "--project", "prod", "--profile", "survival"}, false); err != nil {
		t.Fatal(err)
	}
	local, _, req, err := verifyBridgeLocal02812(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, local, req
}

func TestBridgeVerifyLocalAndRuntime02812(t *testing.T) {
	backend := "http://127.0.0.1:8080"
	root, local, req := fixtureBridge02812(t, backend)
	if !local.LocalVerified || local.RuntimeVerified {
		t.Fatal("runtime must not be certified by local artifact alone")
	}
	when := time.Now().UTC().Format(time.RFC3339Nano)
	node := map[string]any{"id": req.ID, "kind": req.Kind, "projectId": req.ProjectID, "keyFingerprint": req.KeyFingerprint, "pluginVersion": local.Version, "pluginSha256": local.ArtifactSHA256, "protocolVersion": float64(3), "runtimeId": strings.Repeat("a", 64), "lastHeartbeatAt": when, "status": "active", "integrityStatus": "verified"}
	result, err := verifyBridgeRuntime02812(local, req, map[string]any{"data": map[string]any{"items": []any{node}}}, time.Now().UTC())
	if err != nil || !result.RuntimeVerified || result.Status != "healthy" {
		t.Fatalf("runtime=%+v err=%v", result, err)
	}
	cases := []struct {
		name, field string
		value       any
	}{{"wrong hash", "pluginSha256", strings.Repeat("b", 64)}, {"old heartbeat", "lastHeartbeatAt", time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano)}, {"wrong key", "keyFingerprint", strings.Repeat("b", 64)}, {"protocol v2", "protocolVersion", float64(2)}, {"no runtime", "runtimeId", ""}, {"disabled", "status", "disabled"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := map[string]any{}
			for k, v := range node {
				c[k] = v
			}
			c[tc.field] = tc.value
			_, err := verifyBridgeRuntime02812(local, req, map[string]any{"data": map[string]any{"items": []any{c}}}, time.Now().UTC())
			if err == nil {
				t.Fatal("invalid live state certified")
			}
		})
	}
	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	state, _ := readBridgeProvisionState0199(statePath)
	if err := os.WriteFile(state.ArtifactPath, []byte("broken JAR"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := verifyBridgeLocal02812(root); err == nil {
		t.Fatal("tampered installation accepted")
	}
}

func TestBridgeRuntimeVerifyAuthenticatedHTTP02812(t *testing.T) {
	var tokenSeen bool
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenSeen = r.Header.Get("Authorization") == "Bearer secret"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	root, local, req := fixtureBridge02812(t, server.URL)
	body = map[string]any{"data": map[string]any{"items": []any{map[string]any{"id": req.ID, "kind": req.Kind, "projectId": req.ProjectID, "keyFingerprint": req.KeyFingerprint, "pluginVersion": local.Version, "pluginSha256": local.ArtifactSHA256, "protocolVersion": 3, "runtimeId": strings.Repeat("f", 64), "lastHeartbeatAt": time.Now().UTC().Format(time.RFC3339Nano)}}}}
	// Encoding/json uses float64 in decoded maps; HTTP path must accept it.
	if err := verifyServerBridge02812([]string{"verify", "--server-root", root, "--token", "secret"}); err != nil {
		t.Fatal(err)
	}
	if !tokenSeen {
		t.Fatal("authenticated backend GET not executed")
	}
	if err := verifyServerBridge02812([]string{"verify", "--server-root", root, "--offline"}); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeRollBackRejectsForgedTransactions02812(t *testing.T) {
	root, _, _ := fixtureBridge02812(t, "https://example.org")
	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	state, _ := readBridgeProvisionState0199(statePath)
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	os.WriteFile(sentinel, []byte("do not touch"), 0o600)
	txPath := bridgeTransactionPath0199(root, state.TransactionID)
	raw, _ := os.ReadFile(txPath)
	var tx bridgeProvisionTransaction0199
	json.Unmarshal(raw, &tx)
	tx.Changes = append(tx.Changes, bridgeProvisionChange0199{Path: sentinel})
	writeJSONSecure0199(txPath, tx, 0o600)
	if err := rollbackServerBridge0199([]string{"rollback", "--server-root", root, "--transaction", state.TransactionID}); err == nil {
		t.Fatal("forged rollback accepted")
	}
	if text, _ := os.ReadFile(sentinel); string(text) != "do not touch" {
		t.Fatal("external file modified")
	}
	if err := rollbackServerBridge0199([]string{"rollback", "--server-root", root, "--transaction", "../../evil"}); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestBridgeOperatorMutualExclusion02812(t *testing.T) {
	root := t.TempDir()
	unlock, err := bridgeOperatorLock02812(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridgeOperatorLock02812(root); err == nil {
		t.Fatal("concurrent operator accepted")
	}
	unlock()
	done, err := bridgeOperatorLock02812(root)
	if err != nil {
		t.Fatal(err)
	}
	done()
}

func TestBridgeRejectsPlainHTTPAndOutsidePaths02812(t *testing.T) {
	for _, endpoint := range []string{"http://example.org", "https://user:pw@example.org", "https://example.org/?token=secret", "http://10.0.0.1:8080"} {
		if bridgeEndpointSecure02812(endpoint) == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	for _, endpoint := range []string{"https://example.org", "http://127.0.0.1:8080", "http://localhost:8080"} {
		if err := bridgeEndpointSecure02812(endpoint); err != nil {
			t.Fatalf("safe endpoint rejected: %q: %v", endpoint, err)
		}
	}
	root := t.TempDir()
	if err := bridgeInsideRoot02812(root, filepath.Join(t.TempDir(), "outside")); err == nil {
		t.Fatal("outside root accepted")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "escape")); err == nil {
		if err := bridgeInsideRoot02812(root, filepath.Join(root, "escape", "cfg.yml")); err == nil {
			t.Fatal("symlink escape accepted")
		}
	}
}

func TestBridgeRejectsForgedWorldTransaction02812(t *testing.T) {
	root, _, _ := fixtureBridge02812(t, "https://example.org")
	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	state, _ := readBridgeProvisionState0199(statePath)
	world := filepath.Join(root, "world", "playerdata", "test.dat")
	if err := os.MkdirAll(filepath.Dir(world), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(world, []byte("inventory"), 0o600); err != nil {
		t.Fatal(err)
	}
	txPath := bridgeTransactionPath0199(root, state.TransactionID)
	raw, _ := os.ReadFile(txPath)
	var tx bridgeProvisionTransaction0199
	json.Unmarshal(raw, &tx)
	tx.Changes = append(tx.Changes, bridgeProvisionChange0199{Path: world})
	writeJSONSecure0199(txPath, tx, 0o600)
	if err := rollbackServerBridge0199([]string{"rollback", "--server-root", root}); err == nil {
		t.Fatal("world file supplied by tampered journal accepted")
	}
	if raw, _ := os.ReadFile(world); string(raw) != "inventory" {
		t.Fatal("world file was changed")
	}
}

func TestBridgeDryRunDoesNotTakeOperatorLock02812(t *testing.T) {
	root := t.TempDir()
	writeMarkerJar0199(t, filepath.Join(root, "paper.jar"), "io/papermc/paper/configuration/GlobalConfiguration.class")
	dir := t.TempDir()
	writeCertifiedArtifact0199(t, dir, "paper", "0.19.9")
	err := handleServerBridge0199([]string{"install", "--server-root", root, "--artifact-dir", dir, "--bridge-version", "0.19.9", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199))); !os.IsNotExist(err) {
		t.Fatal("dry run created mutable state")
	}
}

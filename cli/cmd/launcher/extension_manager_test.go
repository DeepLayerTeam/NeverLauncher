package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestExtensionManager0425LiveBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/extensions/manager" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"count": 1, "items": []any{map[string]any{"install": map[string]any{"extensionId": "org.example.plugin", "currentState": "enabled", "generation": 7}, "runtime": map[string]any{"state": "running", "pid": 412}}}}})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "live.json")
	if err := handleExtension0201([]string{"manager", "--backend", server.URL, "--token", "token", "--output", path}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if data["data"].(map[string]any)["count"] != float64(1) {
		t.Fatalf("wrong inventory %s", raw)
	}
}
func TestExtensionManager0425RequiresAuthentication(t *testing.T) {
	t.Setenv("LAUNCHER_TOKEN", "")
	if err := handleExtensionManager0425([]string{"--backend", "https://backend.invalid"}); err == nil {
		t.Fatal("missing token accepted")
	}
}

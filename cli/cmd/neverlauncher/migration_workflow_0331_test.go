package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationWorkflowCLI0331(t *testing.T) {
	var endpoint, auth, key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint = r.Method + " " + r.URL.Path
		auth = r.Header.Get("Authorization")
		if r.Method == http.MethodPost {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("invalid body: %v", err)
			}
			key, _ = payload["idempotencyKey"].(string)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"run-123","status":"pending"}}`))
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "run.json")
	if err := handleMigrationWorkflow0331([]string{"create", "--backend", srv.URL, "--token", "test-token", "--project", "p1", "--key", "stable-request-key", "--output", out}); err != nil {
		t.Fatal(err)
	}
	if endpoint != "POST /api/v1/admin/migration-runs" || auth != "Bearer test-token" || key != "stable-request-key" {
		t.Fatalf("request mismatch: %s %s %s", endpoint, auth, key)
	}
	if contents, err := os.ReadFile(out); err != nil || !strings.Contains(string(contents), "run-123") {
		t.Fatalf("invalid JSON output: %s %v", contents, err)
	}
	if err := handleMigrationWorkflow0331([]string{"execute", "--backend", srv.URL, "--token", "test-token"}); err == nil {
		t.Fatal("execution without run ID accepted")
	}
	if err := handleMigrationWorkflow0331([]string{"create", "--backend", srv.URL, "--token", "test-token", "--project", "p1"}); err == nil {
		t.Fatal("missing idempotency key accepted")
	}
}

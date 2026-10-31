package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGravitCompatibilityCLI0332(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.zip")
	if err := os.WriteFile(source, []byte("binary-zip-payload"), 0600); err != nil {
		t.Fatal(err)
	}
	var seen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/admin/migration-runs/run123/compatibility" {
			t.Errorf("wrong method/path: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Gravit-Version") != "5.7.12" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != "application/zip" {
			t.Errorf("missing auth/version/content-type")
		}
		contents, _ := io.ReadAll(r.Body)
		if string(contents) != "binary-zip-payload" {
			t.Error("missing raw ZIP bytes")
		}
		seen = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"manual"}}`))
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "report.json")
	err := handleMigrationWorkflow0331([]string{"assess", "--backend", srv.URL, "--token", "test-token", "--run", "run123", "--source", source, "--version", "5.7.12", "--output", out})
	if err != nil || !seen {
		t.Fatalf("upload failed: %v, seen=%v", err, seen)
	}
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "manual") {
		t.Fatalf("saved report missing: %v %s", err, data)
	}
	if err = handleMigrationWorkflow0331([]string{"assess", "--backend", "http://8.8.8.8", "--token", "t", "--run", "run", "--source", source}); err == nil {
		t.Fatal("cleartext remote secrets allowed")
	}
	if err = handleMigrationWorkflow0331([]string{"assess", "--backend", srv.URL, "--token", "t", "--run", "run"}); err == nil {
		t.Fatal("missing source accepted")
	}
}

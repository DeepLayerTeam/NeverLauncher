package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationReportCLI03313(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing auth")
		}
		if strings.HasSuffix(r.URL.Path, "/review") && r.Method == "POST" {
			if r.Header.Get("X-Migration-RC-Confirm") != "example-run-123" {
				t.Error("missing review confirmation")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"reportSha256":"` + strings.Repeat("a", 64) + `","status":"blocked"}}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "report.json")
	args := []string{"report", "--backend", server.URL, "--token", "test-token", "--run", "example-run-123", "--output", path}
	if e := handleMigrationReport03313(args); e != nil {
		t.Fatal(e)
	}
	if e := handleMigrationReport03313([]string{"report-review", "--backend", server.URL, "--token", "test-token", "--run", "example-run-123", "--report-sha256", strings.Repeat("a", 64), "--evidence-sha256", strings.Repeat("b", 64), "--evidence-reference", "ci/probe/123"}); e == nil {
		t.Fatal("review without confirmation accepted")
	}
	if e := handleMigrationReport03313([]string{"report", "--backend", "http://8.8.8.8", "--token", "t", "--run", "r"}); e == nil {
		t.Fatal("insecure remote backend accepted")
	}
}

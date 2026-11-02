package main

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationContent0337(t *testing.T) {
	file := filepath.Join(t.TempDir(), "src.zip")
	f, e := os.Create(file)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	w, e := z.Create("profiles/demo.json")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = w.Write([]byte(`{"title":"Test"}`))
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	_ = f.Close()
	var gotConfirm, gotPlanSHA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gravit-Profile-Path") != "profiles/demo.json" || r.Header.Get("X-Profile-ID") != "demo" {
			t.Error("missing profile mapping headers")
		}
		gotConfirm = r.Header.Get("X-Migration-Content-Confirm")
		gotPlanSHA = r.Header.Get("X-Migration-Plan-SHA256")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"complete":true,"plan":{"filesSha256":"` + strings.Repeat("f", 64) + `"}}}`))
	}))
	defer server.Close()
	// Local httptest hostname is 127.0.0.1, explicitly permitted.
	err := postMigrationContent0337(server.URL, "token", file, "run-123", "profiles/demo.json", "demo", "", "vanilla", "stable", "1.0", filepath.Join(t.TempDir(), "result.json"), true, strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	if gotPlanSHA != strings.Repeat("a", 64) {
		t.Fatalf("plan SHA missing: %q", gotPlanSHA)
	}
	if gotConfirm != "run-123" {
		t.Fatalf("confirmation lost: %q", gotConfirm)
	}
	if e := postMigrationContent0337("http://example.org/api", "token", file, "run", "profiles/demo.json", "demo", "", "vanilla", "stable", "1.0", "", true, strings.Repeat("a", 64), ""); e == nil || !strings.Contains(e.Error(), "HTTPS") {
		t.Fatal("non-TLS credential transfer accepted")
	}
}

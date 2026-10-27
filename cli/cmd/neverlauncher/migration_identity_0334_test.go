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

func TestMigrationIdentityCLI0334(t *testing.T) {
	var method, path, contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		contentType = r.Header.Get("Content-Type")
		if r.Header.Get("Authorization") != "Bearer token334" {
			t.Error("missing auth token")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"format": "neverlauncher.gravit-identity-map.v1", "ready": false}})
	}))
	defer server.Close()
	base := []string{"--backend", server.URL, "--token", "token334", "--run", "run334"}
	out := filepath.Join(t.TempDir(), "map.json")
	if e := handleMigrationWorkflow0331(append(append([]string{"identities"}, base...), "--output", out)); e != nil {
		t.Fatal(e)
	}
	if method != "GET" || path != "/api/v1/admin/migration-runs/run334/identities" {
		t.Fatalf("wrong GET: %s %s", method, path)
	}
	source := filepath.Join(t.TempDir(), "gravit.zip")
	if e := os.WriteFile(source, []byte("zip identity source"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := handleMigrationWorkflow0331(append(append([]string{"map-identities"}, base...), "--source", source, "--output", filepath.Join(t.TempDir(), "mapping.json"))); e != nil {
		t.Fatal(e)
	}
	if method != "POST" || contentType != "application/zip" {
		t.Fatalf("wrong upload: %s %s", method, contentType)
	}
	if e := handleMigrationWorkflow0331(append([]string{"verify-identities"}, base...)); e != nil {
		t.Fatal(e)
	}
	if method != "POST" || !strings.HasSuffix(path, "/identities/verify") {
		t.Fatalf("wrong verify %s %s", method, path)
	}
}

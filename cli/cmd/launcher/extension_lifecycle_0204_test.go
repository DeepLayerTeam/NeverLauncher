package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestExtensionLifecycleInstallCLI0204(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/extension-installs/example.lifecycle/install" || r.Method != http.MethodPost {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer lifecycle-token" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["scope"] != "project" || body["scopeId"] != "project-a" || body["version"] != "1.2.3" {
			t.Fatalf("body=%v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"status":"installed"}}`)
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "install.json")
	if err := handleExtensionLifecycle0204("install", []string{"example.lifecycle@1.2.3", "--backend", server.URL, "--token", "lifecycle-token", "--scope", "project", "--scope-id", "project-a", "--output", out}); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionLifecycleUpdateChannelCLI0204(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/extension-installs/example.lifecycle/update" || r.Method != http.MethodPost {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["scope"] != "global" || body["channel"] != "beta" {
			t.Fatalf("body=%v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"status":"updated"}}`)
	}))
	defer server.Close()
	if err := handleExtensionLifecycle0204("update", []string{"example.lifecycle", "--backend", server.URL, "--token", "lifecycle-token", "--channel", "beta"}); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionLifecycleStatusCLI0204(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/extension-installs/example.lifecycle" || r.Method != http.MethodGet {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("scope") != "project" || r.URL.Query().Get("scopeId") != "project-a" {
			t.Fatalf("query=%s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"install":{"extensionId":"example.lifecycle"}}}`)
	}))
	defer server.Close()
	if err := handleExtensionLifecycle0204("status", []string{"example.lifecycle", "--backend", server.URL, "--token", "lifecycle-token", "--scope", "project", "--scope-id", "project-a"}); err != nil {
		t.Fatal(err)
	}
}

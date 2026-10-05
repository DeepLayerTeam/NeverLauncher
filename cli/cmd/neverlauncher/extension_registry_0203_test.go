package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtensionRegistrySearchCLI0203(t *testing.T) {
	var seen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/extension-registry/extensions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer registry-token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		q := r.URL.Query()
		expected := map[string]string{"q": "sample", "channel": "stable", "launcherVersion": "0.20.3", "os": "linux", "arch": "amd64"}
		for key, value := range expected {
			if q.Get(key) != value {
				t.Fatalf("query %s=%q want %q", key, q.Get(key), value)
			}
		}
		seen = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"schemaVersion":"1.0","count":0,"items":[]}}`)
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "search.json")
	err := handleExtensionRegistry0203([]string{"search", "sample", "--backend", server.URL, "--token", "registry-token", "--channel", "stable", "--launcher-version", "0.20.3", "--os", "linux", "--arch", "amd64", "--output", out})
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("registry search request was not received")
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["data"]; !ok {
		t.Fatalf("unexpected payload: %s", raw)
	}
}

func TestExtensionRegistryInstallCLI0203(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/extension-registry/extensions/example.registry-extension/versions/1.2.3/install" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["scope"] != "project" || body["scopeId"] != "project-a" {
			t.Fatalf("body=%v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"status":"installed","verified":true}}`)
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "install.json")
	err := handleExtensionRegistry0203([]string{"install", "example.registry-extension@1.2.3", "--backend", server.URL, "--token", "registry-token", "--scope", "project", "--scope-id", "project-a", "--output", out})
	if err != nil {
		t.Fatal(err)
	}
}

func TestExtensionRegistryPullRejectsBadSHA0203(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+strings.Repeat("0", 64)+`"`)
		w.Header().Set("X-NeverLauncher-Package-Identity", "sha256:"+strings.Repeat("1", 64))
		_, _ = io.WriteString(w, "tampered artifact")
	}))
	defer server.Close()
	dest := filepath.Join(t.TempDir(), "artifact.nlext")
	err := extensionRegistryPullCLI0203(server.URL, "registry-token", "example.registry-extension", "1.2.3", dest)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("error=%v, want SHA-256 failure", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("destination should not exist after failed verification: %v", statErr)
	}
}

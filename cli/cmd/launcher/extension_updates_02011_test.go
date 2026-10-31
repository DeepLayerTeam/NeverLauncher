package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtensionUpdatesCLI02011PlanPayload(t *testing.T) {
	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/extension-updates/plan" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing bearer token: %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"1.0","data":{"ok":true}}`))
	}))
	defer ts.Close()
	out := filepath.Join(t.TempDir(), "plan.json")
	if err := handleExtensionUpdates02011([]string{"plan", "example.ext@1.2.3", "--backend", ts.URL, "--token", "test-token", "--output", out, "--channel", "beta", "--scope", "project", "--scope-id", "project-1"}); err != nil {
		t.Fatal(err)
	}
	if got["scope"] != "project" || got["scopeId"] != "project-1" || got["channel"] != "beta" {
		t.Fatalf("unexpected update request: %#v", got)
	}
	roots, ok := got["roots"].([]any)
	if !ok || len(roots) != 1 {
		t.Fatalf("unexpected roots: %#v", got["roots"])
	}
	root := roots[0].(map[string]any)
	if root["extensionId"] != "example.ext" || root["version"] != "1.2.3" || root["channel"] != "beta" {
		t.Fatalf("unexpected root: %#v", root)
	}
}

func TestExtensionUpdatesCLI02011RoutesAndRejectsUnknownChannel(t *testing.T) {
	if err := handleExtension0201([]string{"updates"}); err == nil || !strings.Contains(err.Error(), "extension updates") {
		t.Fatalf("updates command not routed: %v", err)
	}
	if err := handleExtensionUpdates02011([]string{"plan", "example.ext", "--backend", "http://127.0.0.1:1", "--token", "x", "--channel", "nightly"}); err == nil {
		t.Fatal("unsupported update channel accepted")
	}
}

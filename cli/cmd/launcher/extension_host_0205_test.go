package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtensionHostCLI0205(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer host-token" {
			t.Fatalf("missing auth: %q", r.Header.Get("Authorization"))
		}
		if calls == 1 {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/extension-hosts" {
				t.Fatalf("unexpected list %s %s", r.Method, r.URL.Path)
			}
		}
		if calls == 2 {
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/extension-hosts/example.host/restart" || r.URL.Query().Get("scope") != "project" || r.URL.Query().Get("scopeId") != "project-a" {
				t.Fatalf("unexpected restart %s %s %s", r.Method, r.URL.String(), r.URL.RawQuery)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"ok":true}}`)
	}))
	defer server.Close()
	if err := handleExtensionHost0205([]string{"list", "--backend", server.URL, "--token", "host-token"}); err != nil {
		t.Fatal(err)
	}
	if err := handleExtensionHost0205([]string{"restart", "example.host", "--backend", server.URL, "--token", "host-token", "--scope", "project", "--scope-id", "project-a"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

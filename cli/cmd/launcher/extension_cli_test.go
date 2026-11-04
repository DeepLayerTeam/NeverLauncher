package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtensionCLINamespaceCatalogAndInvoke0209(t *testing.T) {
	invoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/extension-cli/catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"protocol": extensionCLIProtocol0209, "items": []any{map[string]any{"extensionId": "example.cli", "name": "Example", "version": "1.0.0", "scope": "global", "cli": map[string]any{"namespace": "ops", "commands": []any{map[string]any{"name": "status"}}}}}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/extension-cli/example.cli/invoke":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["command"] != "status" {
				t.Errorf("command=%v", req["command"])
			}
			invoked = true
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"exitCode": 0, "stdout": "ok\n", "protocol": "1.0"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	items, err := fetchExtensionCLICatalog0209(srv.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].CLI.Namespace != "ops" {
		t.Fatalf("catalog=%#v", items)
	}
	if err := invokeExtensionNamespace0209(srv.URL, "token", items, "ops", "status", "global", "", nil); err != nil {
		t.Fatal(err)
	}
	if !invoked {
		t.Fatal("invoke endpoint not called")
	}
	script, err := extensionCLICompletion0209("bash", items, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "ops") || !strings.Contains(script, "status") {
		t.Fatalf("completion=%s", script)
	}
}

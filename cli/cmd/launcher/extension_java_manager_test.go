package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestJavaManagerDiagnoseCLI0305(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/extension-installs/example.java" || r.URL.Query().Get("diagnostics") != "1" || r.URL.Query().Get("scope") != "project" || r.URL.Query().Get("scopeId") != "p1" {
			t.Errorf("request=%s %s", r.Method, r.URL.String())
			http.Error(w, "bad", 400)
			return
		}
		if r.Header.Get("Authorization") != "Bearer manager-token" {
			t.Error("missing manager authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"apiVersion":"1","data":{"javaDiagnostics":{"healthy":true,"javaTargets":[{"javaMinimum":17}]}}}`)
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "diagnostics.json")
	if err := handleExtensionLifecycle0204("diagnose", []string{"example.java", "--backend", server.URL, "--token", "manager-token", "--scope", "project", "--scope-id", "p1", "--output", output}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data struct {
			JavaDiagnostics struct {
				Healthy bool `json:"healthy"`
			} `json:"javaDiagnostics"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Data.JavaDiagnostics.Healthy {
		t.Fatal("diagnostic data omitted")
	}
}

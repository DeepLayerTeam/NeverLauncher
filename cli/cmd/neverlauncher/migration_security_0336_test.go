package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMigrationSecurityCLI0336(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("X-Migration-Trust-Confirm") != "run-1" || r.Header.Get("X-Migration-Fresh-Keys-Confirmed") != "true" {
			t.Error("missing safety confirmation")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"verified":true,"readyForCutover":false}}`))
	}))
	defer srv.Close()
	if err := postMigrationSecurity0336(srv.URL, "t", "run-1", "", true, ""); err == nil {
		t.Fatal("missing confirmation accepted")
	}
	if calls != 0 {
		t.Fatal("unsafe request sent")
	}
	if err := postMigrationSecurity0336("http://example.com/api", "t", "run-1", "", true, "run-1"); err == nil {
		t.Fatal("insecure remote HTTP accepted")
	}
	if err := postMigrationSecurity0336(srv.URL, "t", "run-1", "", true, "run-1"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("activate not executed")
	}
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		t.Skip("system selected IPv6 loopback")
	}
}

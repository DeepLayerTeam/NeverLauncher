package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalAuthCLI0295ExportRedactsUnknownServerFields(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_ADMIN_ACCESS_TOKEN", "test-token")
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/users" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unauthorized endpoint %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"items":[{"id":"test","email":"test@example.invalid","status":"active","roleId":"player","passwordHash":"SECRET_HASH","refreshToken":"SECRET_TOKEN","session":{"accessToken":"SECRET"}}]}`))
	}))
	defer remote.Close()
	var output bytes.Buffer
	err := run([]string{"export", "--api", remote.URL}, &output, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET_HASH", "SECRET_TOKEN", "refreshToken", "passwordHash", "session"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("secret leaked into export: %q", secret)
		}
	}
	var parsed map[string]any
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
}
func TestLocalAuthCLI0295PasswordOnlyFromStdin(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_ADMIN_ACCESS_TOKEN", "test-token")
	secret := "Safe-Password-0295"
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/users/u-1/password" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("bad protected route %s", r.URL.Path)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["password"] != secret {
			t.Error("password not delivered over protected API request")
		}
		_, _ = w.Write([]byte(`{"revokedSessions":2,"user":{"id":"u-1"}}`))
	}))
	defer remote.Close()
	var output bytes.Buffer
	if err := run([]string{"password", "--api", remote.URL, "--user-id", "u-1"}, &output, strings.NewReader(secret+"\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("password leaked to CLI output")
	}
}
func TestLocalAuthCLI0295SecurityRefusals(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_ADMIN_ACCESS_TOKEN", "test-token")
	var output bytes.Buffer
	if err := run([]string{"list", "--api", "http://public.example.invalid"}, &output, strings.NewReader("")); err == nil {
		t.Fatal("remote cleartext HTTP accepted")
	}
	if err := run([]string{"create", "--api", "https://api.example.invalid", "--email", "admin@fileauth.invalid"}, &output, strings.NewReader("LongPassword0295\n")); err == nil {
		t.Fatal("reserved FileAuth domain accepted")
	}
	if err := run([]string{"import", "--file", "/tmp/Sessions.json", "--format", "sha256-hex"}, &output, strings.NewReader("")); err == nil {
		t.Fatal("Sessions.json import accepted")
	}
}

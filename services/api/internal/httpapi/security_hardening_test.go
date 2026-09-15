package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestSecurityHardening902TOTPAndPasswordReset(t *testing.T) {
	api := Server{Version: "9.0.2", Config: config.Config{PublicURL: "http://127.0.0.1:18092", AuthTokenSecret: "test-secret"}, Repo: repository.NewMemoryRepository("http://127.0.0.1:18092"), State: NewRuntimeState()}
	h := api.Handler()

	login := postJSON902(t, h, "/api/v1/admin/login", `{"email":"admin@neverlauncher.local","password":"admin"}`, "")
	token := stringField902(t, login, "token")
	if token == "" {
		t.Fatalf("admin login did not return token: %#v", login)
	}

	enroll := postJSON902(t, h, "/api/v1/auth/totp/enroll", `{}`, token)
	code := nestedStringField902(t, enroll, "data", "currentCodeForSmoke")
	if code == "" {
		t.Fatalf("enroll did not return currentCodeForSmoke: %#v", enroll)
	}
	verify := postJSON902(t, h, "/api/v1/auth/totp/verify", `{"code":"`+code+`"}`, token)
	if nestedStringField902(t, verify, "data", "status") != "totp-enabled" {
		t.Fatalf("totp was not enabled: %#v", verify)
	}

	withoutMFA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin"}`))
	withoutMFA.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, withoutMFA)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("login without TOTP should fail after MFA enablement, got %d: %s", res.Code, res.Body.String())
	}

	withMFA := postJSON902(t, h, "/api/v1/auth/login", `{"email":"admin@neverlauncher.local","password":"admin","totp":"`+currentTOTPCode902(api.State.Security.mfa["admin"].ActiveSecret, nowUTC902())+`"}`, "")
	if nestedStringField902(t, withMFA, "data", "status") != "authenticated" {
		t.Fatalf("login with TOTP failed: %#v", withMFA)
	}

	reset := postJSON902(t, h, "/api/v1/auth/password-reset/request", `{"email":"admin@neverlauncher.local"}`, "")
	resetToken := nestedStringField902(t, reset, "data", "token")
	if resetToken == "" {
		t.Fatalf("reset token missing: %#v", reset)
	}
	confirm := postJSON902(t, h, "/api/v1/auth/password-reset/confirm", `{"token":"`+resetToken+`","password":"ChangeMe-9.0.2-secure"}`, "")
	if nestedStringField902(t, confirm, "data", "status") != "password-updated" {
		t.Fatalf("password reset did not update password: %#v", confirm)
	}
}

func postJSON902(t *testing.T, h http.Handler, path, body, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code < 200 || res.Code >= 300 {
		t.Fatalf("%s returned %d: %s", path, res.Code, res.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json from %s: %v", path, err)
	}
	return payload
}

func stringField902(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	if v, ok := payload[key].(string); ok {
		return v
	}
	return ""
}

func nestedStringField902(t *testing.T, payload map[string]any, first, second string) string {
	t.Helper()
	nested, ok := payload[first].(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := nested[second].(string); ok {
		return v
	}
	return ""
}

func nowUTC902() time.Time { return time.Now().UTC() }

func TestAdminLoginDoesNotFallbackToConfigPassword(t *testing.T) {
	repo := repository.NewMemoryRepository("http://127.0.0.1:18092")
	if _, err := repo.SetUserPassword("admin", hashPassword("Strong-New-Password-902")); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.10.0-P3.2v4", Config: config.Config{PublicURL: "http://127.0.0.1:18092", AuthTokenSecret: "test-secret"}, Repo: repo, State: NewRuntimeState()}
	h := api.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("старый пароль не должен обходить хеш пользователя: got %d %s", res.Code, res.Body.String())
	}
}

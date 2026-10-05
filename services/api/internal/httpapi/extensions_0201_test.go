package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func extensionAdminToken0201(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("login: %d %s", res.Code, res.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &session); err != nil || session.Token == "" {
		t.Fatalf("login token: %v %s", err, res.Body.String())
	}
	return session.Token
}

func TestNeverExtensionsCoreHTTP0201(t *testing.T) {
	h := p1CanonicalServer(t)
	token := extensionAdminToken0201(t, h)
	manifest := `{
		"schemaVersion":"2.0",
		"id":"ru.example.http-extension",
		"name":"HTTP Extension",
		"version":"1.0.0",
		"publisher":"Example Publisher",
		"api":"3.7",
		"targets":[{"kind":"backend","entrypoint":"bin/backend"}],
		"permissions":["release:read"],
		"dependencies":[{"id":"ru.example.base","version":">=1.0.0","optional":true}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/extensions/versions", strings.NewReader(manifest))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), `"manifestSha256"`) {
		t.Fatalf("register extension: %d %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/extensions/ru.example.http-extension/versions/1.0.0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"ru.example.http-extension"`) {
		t.Fatalf("get extension version: %d %s", res.Code, res.Body.String())
	}

	mutated := strings.Replace(manifest, "HTTP Extension", "Mutated Extension", 1)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/extensions/versions", strings.NewReader(mutated))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("immutable version mutation must conflict: %d %s", res.Code, res.Body.String())
	}
}

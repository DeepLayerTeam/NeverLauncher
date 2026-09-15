package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func p1CanonicalServer(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Config{
		PublicURL:                 "http://example.test",
		RepositoryDriver:          "memory",
		StorageDriver:             "local",
		StorageLocalPath:          t.TempDir(),
		Environment:               "dev",
		AuthTokenSecret:           "p1-contract-test-secret",
		AuthTokenTTLHours:         1,
		ManifestSigningPrivateKey: p1TestSigningSeed,
	}
	return Server{
		Version: "0.10.0-P3.2v4",
		Config:  cfg,
		Repo:    repository.NewMemoryRepository(cfg.PublicURL),
		Storage: storage.NewLocalStorage(cfg.StorageLocalPath),
		State:   NewRuntimeState(),
	}.Handler()
}

func TestCanonicalRouterDisablesHistoricalAPIByDefault(t *testing.T) {
	h := p1CanonicalServer(t)
	for _, path := range []string{"/api/v2/status", "/api/v3/status", "/api/v4/status", "/api/v5/status"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusNotFound {
			t.Fatalf("historical route %s must be disabled, got %d: %s", path, res.Code, res.Body.String())
		}
	}
}

func TestHistoricalRoutesRemainRemoved(t *testing.T) {
	h := p1CanonicalServer(t)
	for _, path := range []string{"/api/v2/status", "/api/v3/status", "/api/v4/status", "/api/v5/status"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusNotFound {
			t.Fatalf("historical route %s must remain removed, got %d: %s", path, res.Code, res.Body.String())
		}
	}
}

func TestCanonicalCRUDUsesSingleContractVersion(t *testing.T) {
	h := p1CanonicalServer(t)
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

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects", strings.NewReader(`{"id":"p1-project","name":"P1 Project","defaultChannel":"stable"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session.Token)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"apiVersion":"1.0.0"`) || strings.Contains(res.Body.String(), "8.2.0") {
		t.Fatalf("canonical CRUD leaked historical contract metadata: %s", res.Body.String())
	}
}

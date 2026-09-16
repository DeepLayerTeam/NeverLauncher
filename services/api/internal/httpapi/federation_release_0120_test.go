package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestGenericBrowserProviderExplicitLink0120(t *testing.T) {
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), AuthTokenSecret: "0123456789abcdef0123456789abcdef-release"}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	core := federation.New(repo)
	if err := core.Register(localAuthConnector112{repo: repo}); err != nil {
		t.Fatal(err)
	}
	if err := core.RegisterWithPolicy(oidcFixtureConnector115{}, federation.ProviderPolicy{AutoProvision: false}); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.12.0", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath), State: NewRuntimeState(), Federation: core}
	admin, err := repo.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := api.issueLoginSession(admin, httptest.NewRequest(http.MethodGet, "/", nil), "release-test")
	if err != nil {
		t.Fatal(err)
	}
	h := api.Handler()

	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/providers/oidc-fixture/link/begin", strings.NewReader(`{}`))
	beginReq.Header.Set("Authorization", "Bearer "+access)
	beginReq.Header.Set("Content-Type", "application/json")
	beginRes := httptest.NewRecorder()
	h.ServeHTTP(beginRes, beginReq)
	if beginRes.Code != http.StatusOK {
		t.Fatalf("begin status=%d body=%s", beginRes.Code, beginRes.Body.String())
	}
	var begin struct {
		Data struct {
			State       string `json:"state"`
			Transaction string `json:"transaction"`
		} `json:"data"`
	}
	if err := json.Unmarshal(beginRes.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"code": "fixture-code", "state": begin.Data.State, "transaction": begin.Data.Transaction})
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/providers/oidc-fixture/link/complete", strings.NewReader(string(body)))
	completeReq.Header.Set("Authorization", "Bearer "+access)
	completeReq.Header.Set("Content-Type", "application/json")
	completeRes := httptest.NewRecorder()
	h.ServeHTTP(completeRes, completeReq)
	if completeRes.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", completeRes.Code, completeRes.Body.String())
	}
	identity, err := repo.GetAuthIdentity("oidc-fixture", "oidc-user-42")
	if err != nil || identity.UserID != "admin" {
		t.Fatalf("generic OIDC identity not linked to current user: %+v err=%v", identity, err)
	}
}

func TestFederationStatus0120ReportsProviderHealth(t *testing.T) {
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), AuthTokenSecret: "0123456789abcdef0123456789abcdef-release"}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	core, err := NewFederationCore112(repo)
	if err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.12.0", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath), State: NewRuntimeState(), Federation: core}
	admin, _ := repo.GetUser("admin")
	access, _, _, err := api.issueLoginSession(admin, httptest.NewRequest(http.MethodGet, "/", nil), "release-test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/auth/federation/status", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res := httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"ready":true`) || !strings.Contains(res.Body.String(), `"id":"local"`) {
		t.Fatalf("federation status=%d body=%s", res.Code, res.Body.String())
	}
}

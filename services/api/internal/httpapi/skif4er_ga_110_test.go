package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Real HTTP transport and canonical repositories/session machinery. Only the upstream
// IdP is a fixture; real Keycloak acceptance is separate.
func TestSkif4erGA110CrossClientLifecycle(t *testing.T) {
	exerciseSkif4erCrossClientLifecycle(t, false)
}

func TestUnifiedIntegration130CrossClientLifecycle(t *testing.T) {
	exerciseSkif4erCrossClientLifecycle(t, true)
}

func exerciseSkif4erCrossClientLifecycle(t *testing.T, unified bool) {
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), AuthTokenSecret: strings.Repeat("x", 48)}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	core := federation.New(repo)
	if err := core.Register(localAuthConnector112{repo: repo}); err != nil {
		t.Fatal(err)
	}
	if err := core.RegisterWithPolicy(skiMFAFixture104{}, federation.ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	s := Server{Version: "1.1.0", Config: cfg, Repo: repo, State: NewRuntimeState(), Federation: core, Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}
	s.State.RateLimitEnabled = false
	var fixture *unifiedAIFixture130
	if unified {
		s.Version = "1.3.0"
		fixture = newUnifiedAIFixture130(t)
		s.AI = fixture.gateway
	}
	api := httptest.NewServer(s.Handler())
	defer api.Close()
	api.Client().Timeout = 30 * time.Second
	call := func(method, path, bearer string, body any, want int) map[string]any {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(method, api.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := api.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		payload, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: status %d want %d: %s", method, path, res.StatusCode, want, payload)
		}
		var result map[string]any
		if err := json.Unmarshal(payload, &result); err != nil {
			t.Fatal(err)
		}
		if data, ok := result["data"].(map[string]any); ok {
			return data
		}
		return result
	}
	const oidc = "/api/v1/auth/oidc/skif4er-id"
	const link = "/api/v1/auth/providers/skif4er-id/link"
	const web = "https://admin.example.test/auth/skif4er/callback"
	const desktop = "http://127.0.0.1:8765/callback"
	admin, err := repo.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	local, _, _, err := s.issueLoginSession(admin, httptest.NewRequest("GET", "/", nil), "admin-browser")
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := repo.SaveUser(model.User{ID: "ga-other", Email: "other@example.test", Status: "active", RoleID: "player", PasswordHash: "test-hash"})
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := s.issueLoginSession(otherUser, httptest.NewRequest("GET", "/", nil), "admin-browser")
	if err != nil {
		t.Fatal(err)
	}
	begin := func(path, redirect, device, token string) map[string]any {
		t.Helper()
		data := call("POST", path+"/begin", token, map[string]string{"redirectUri": redirect, "deviceId": device}, 200)
		return map[string]any{"state": data["state"], "transaction": data["transaction"], "code": "fixture-code", "deviceId": device}
	}
	cb := begin(link, web, "admin-browser", local)
	call("POST", link+"/complete", other, cb, 401)
	proof := call("POST", link+"/complete", local, cb, 200)
	id := proof["identity"].(map[string]any)["id"].(string)
	call("POST", link+"/complete", local, cb, 401)
	call("POST", link+"/complete", other, begin(link, web, "admin-browser", other), 409)
	login := func(redirect, device string) map[string]any {
		t.Helper()
		cb := begin(oidc, redirect, device, "")
		data := call("POST", oidc+"/complete", "", cb, 200)
		if data["user"].(map[string]any)["id"] != "admin" || data["identity"].(map[string]any)["id"] != id {
			t.Fatal("cross-client canonical identity changed")
		}
		call("POST", oidc+"/complete", "", cb, 401)
		return data["tokens"].(map[string]any)
	}
	dt := login(desktop, "desktop-client")
	at := login(web, "admin-browser")
	access := at["accessToken"].(string)
	if unified {
		fixture.complete(t, api, dt["accessToken"].(string))
		call("GET", "/api/v1/ai/usage", other, nil, 403)
		usage := call("GET", "/api/v1/ai/usage", access, nil, 200)["usage"].(map[string]any)
		if usage["requests"] != float64(1) || usage["chargedMicroUsd"] != float64(18) {
			t.Fatalf("desktop usage not visible to same canonical account: %v", usage)
		}
	}
	me := call("GET", "/api/v1/admin/me", access, nil, 200)
	if me["user"].(map[string]any)["roleId"] != admin.RoleID {
		t.Fatal("local role changed")
	}
	rotated := call("POST", "/api/v1/auth/refresh", "", map[string]any{"refreshToken": at["refreshToken"]}, 200)["tokens"].(map[string]any)
	access = rotated["accessToken"].(string)
	if unified {
		fixture.complete(t, api, access)
		usage := call("GET", "/api/v1/ai/usage", dt["accessToken"].(string), nil, 200)["usage"].(map[string]any)
		if usage["requests"] != float64(2) || usage["chargedMicroUsd"] != float64(36) {
			t.Fatalf("rotation changed canonical AI budget: %v", usage)
		}
	}
	call("POST", "/api/v1/auth/logout", access, nil, 200)
	call("GET", "/api/v1/admin/me", access, nil, 401)
	call("POST", "/api/v1/auth/refresh", "", map[string]any{"refreshToken": rotated["refreshToken"]}, 401)
	call("DELETE", "/api/v1/auth/identities/"+id, other, nil, 404)
	var stalled *http.Response
	if unified {
		call("POST", "/api/v1/ai/responses", access, map[string]string{"prompt": "hello"}, 401)
		stalled = fixture.stream(t, api, dt["accessToken"].(string))
		defer stalled.Body.Close()
		select {
		case <-fixture.stalled:
		case <-time.After(10 * time.Second):
			t.Fatal("provider was not reached")
		}
	}
	call("DELETE", "/api/v1/auth/identities/"+id, local, nil, 200)
	if unified {
		body, err := io.ReadAll(stalled.Body)
		if err != nil || !strings.Contains(string(body), `"code":"access_revoked"`) || strings.Contains(string(body), "event: done") {
			t.Fatalf("unlink did not terminate active AI stream: %s %v", body, err)
		}
		call("POST", "/api/v1/ai/responses", dt["accessToken"].(string), map[string]string{"prompt": "hello"}, 401)
		usage := call("GET", "/api/v1/ai/usage", local, nil, 200)["usage"].(map[string]any)
		if usage["requests"] != float64(3) || usage["chargedMicroUsd"] != float64(4388) || usage["uncertainRequests"] != float64(1) {
			t.Fatalf("interrupted generation lost reservation: %v", usage)
		}
		call("POST", "/api/v1/ai/responses", local, map[string]string{"prompt": "hello"}, 429)
		if fixture.calls.Load() != 3 {
			t.Fatal("rejected request reached provider")
		}
	}
	call("GET", "/api/v1/auth/identities", dt["accessToken"].(string), nil, 401)
	call("POST", "/api/v1/auth/refresh", "", map[string]any{"refreshToken": dt["refreshToken"]}, 401)
	call("GET", "/api/v1/admin/me", local, nil, 200)
	seen := map[string]bool{}
	for _, event := range repo.ListAuditEvents() {
		seen[event.Action] = true
	}
	for _, action := range []string{"auth:provider:linked", "auth:federation:authenticated", "auth:provider:unlinked", "auth:logout"} {
		if !seen[action] {
			t.Errorf("missing audit %s", action)
		}
	}
}

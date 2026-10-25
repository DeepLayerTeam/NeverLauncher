package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type apiRouteFixture0293 struct {
	id     string
	reject bool
	calls  *int
}

func (f apiRouteFixture0293) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: f.id, DisplayName: f.id, Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (f apiRouteFixture0293) Health(context.Context) error { return nil }
func (f apiRouteFixture0293) AuthenticatePassword(_ context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	*f.calls++
	if f.reject || req.Secret != "verified" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid password")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "other-account", Issuer: "https://external.test", Email: req.Identifier}, AuthMethods: []string{"password"}}, nil
}

func TestHTTPLoginRouting0293NoFallbackAndStrictDomain(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core, err := NewFederationCore112(repo)
	if err != nil {
		t.Fatal(err)
	}
	first, second := 0, 0
	if err := core.Register(apiRouteFixture0293{id: "primary", reject: true, calls: &first}); err != nil {
		t.Fatal(err)
	}
	if err := core.Register(apiRouteFixture0293{id: "secondary", calls: &second}); err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(federation.RoutingConfig{Version: 1, DefaultProvider: "local", Rules: []federation.RoutingRule{{EmailDomain: "company.test", ProviderID: "primary", Strict: true}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "secondary", Issuer: "https://external.test", Subject: "other-account"}); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.29.3", Config: config.Config{Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: "012345678901234567890123456789012345"}, Repo: repo, State: NewRuntimeState(), Federation: core}
	h := api.Handler()
	request := func(payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		result := httptest.NewRecorder()
		h.ServeHTTP(result, req)
		return result
	}
	res := request(`{"identifier":"alice@company.test","password":"verified"}`)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("primary auth failure status=%d body=%s", res.Code, res.Body.String())
	}
	if first != 1 || second != 0 {
		t.Fatalf("unexpected fallback: primary=%d secondary=%d", first, second)
	}
	res = request(`{"identifier":"alice@company.test","password":"verified","providerId":"secondary"}`)
	if res.Code != http.StatusForbidden || second != 0 {
		t.Fatalf("strict domain bypass status=%d calls=%d", res.Code, second)
	}
	res = request(`{"identifier":"alice@other.test","password":"verified","providerId":"secondary"}`)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"issuer":"https://external.test"`) {
		t.Fatalf("explicit issuer-scoped login status=%d body=%s", res.Code, res.Body.String())
	}
	if second != 1 {
		t.Fatalf("explicit provider not called: %d", second)
	}
}

func TestHTTPLinkBlockedBeforeCredentialProof0293(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core, err := NewFederationCore112(repo)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := core.Register(apiRouteFixture0293{id: "blocked", calls: &calls}); err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(federation.RoutingConfig{Version: 1, DefaultProvider: "local", DisableLinking: true}); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.29.3", Config: config.Config{Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: "012345678901234567890123456789012345"}, Repo: repo, State: NewRuntimeState(), Federation: core}
	admin, err := repo.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := api.issueLoginSession(admin, httptest.NewRequest(http.MethodGet, "/", nil), "device")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/providers/blocked/link/password", strings.NewReader(`{"identifier":"test","password":"verified"}`))
	req.Header.Set("Authorization", "Bearer "+access)
	res := httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("link policy status=%d body=%s", res.Code, res.Body.String())
	}
	if calls != 0 {
		t.Fatal("disabled linking sent credentials to external provider")
	}
	if !errors.Is(core.EnsureLinkAllowed("blocked"), federation.ErrLinkingDisabled) {
		t.Fatal("link protection absent")
	}
}

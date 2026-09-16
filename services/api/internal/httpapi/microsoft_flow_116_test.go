package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type microsoftFixtureConnector116 struct{}

func (microsoftFixtureConnector116) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "ms-fixture", DisplayName: "Microsoft Fixture", Version: "0.11.6", Capabilities: []authconnector.Capability{authconnector.CapabilityBrowserAuth, authconnector.CapabilityTokenRefresh, authconnector.CapabilityEmail}}
}
func (microsoftFixtureConnector116) Health(context.Context) error { return nil }
func (microsoftFixtureConnector116) ProviderKind() string         { return "microsoft" }
func (microsoftFixtureConnector116) DefaultRedirectURI() string {
	return "https://launcher.example.test/api/v1/auth/oidc/ms-fixture/callback"
}
func (microsoftFixtureConnector116) BeginBrowserAuth(_ context.Context, req authconnector.BrowserAuthRequest) (authconnector.BrowserAuthStart, error) {
	u, _ := url.Parse("https://login.microsoftonline.test/authorize")
	q := u.Query()
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", req.PKCEChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return authconnector.BrowserAuthStart{AuthorizationURL: u.String(), State: req.State, ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
}
func (microsoftFixtureConnector116) CompleteBrowserAuth(_ context.Context, cb authconnector.BrowserAuthCallback) (authconnector.Authentication, error) {
	if cb.Code != "microsoft-code" || len(cb.PKCEVerifier) < 43 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid fixture code")
	}
	return microsoftFixtureAuth116("microsoft-refresh-secret"), nil
}
func (microsoftFixtureConnector116) Refresh(_ context.Context, token string) (authconnector.Authentication, error) {
	if token != "microsoft-refresh-secret" && token != "microsoft-refresh-rotated" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid refresh token")
	}
	return microsoftFixtureAuth116("microsoft-refresh-rotated"), nil
}
func (microsoftFixtureConnector116) ProviderLogoutURL(redirect string) (string, error) {
	return "https://login.microsoftonline.test/logout?post_logout_redirect_uri=" + url.QueryEscape(redirect), nil
}
func microsoftFixtureAuth116(token string) authconnector.Authentication {
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "11111111-2222-3333-4444-555555555555:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Email: "ms@example.test", DisplayName: "Microsoft User", Claims: map[string]any{"tid": "11111111-2222-3333-4444-555555555555", "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}, AuthMethods: []string{"oidc", "microsoft"}, ProviderToken: token}
}

func TestMicrosoftExplicitLinkStoresEncryptedCredentialAndRotates116(t *testing.T) {
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), AuthTokenSecret: "0123456789abcdef0123456789abcdef-microsoft-flow"}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	core := federation.New(repo)
	if err := core.RegisterWithPolicy(microsoftFixtureConnector116{}, federation.ProviderPolicy{AutoProvision: false}); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.11.6", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath), State: NewRuntimeState(), Federation: core}
	admin, err := repo.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	access, _, _, err := api.issueLoginSession(admin, seedReq, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	handler := api.Handler()

	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/microsoft/ms-fixture/link/begin", strings.NewReader(`{}`))
	beginReq.Header.Set("Authorization", "Bearer "+access)
	beginReq.Header.Set("Content-Type", "application/json")
	beginRes := httptest.NewRecorder()
	handler.ServeHTTP(beginRes, beginReq)
	if beginRes.Code != http.StatusOK {
		t.Fatalf("link begin status=%d body=%s", beginRes.Code, beginRes.Body.String())
	}
	var begin struct {
		Data struct{ State, Transaction string } `json:"data"`
	}
	if err := json.Unmarshal(beginRes.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	completeBody, _ := json.Marshal(map[string]any{"code": "microsoft-code", "state": begin.Data.State, "transaction": begin.Data.Transaction})
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/microsoft/ms-fixture/link/complete", strings.NewReader(string(completeBody)))
	completeReq.Header.Set("Authorization", "Bearer "+access)
	completeReq.Header.Set("Content-Type", "application/json")
	completeRes := httptest.NewRecorder()
	handler.ServeHTTP(completeRes, completeReq)
	if completeRes.Code != http.StatusOK {
		t.Fatalf("link complete status=%d body=%s", completeRes.Code, completeRes.Body.String())
	}
	if strings.Contains(completeRes.Body.String(), "microsoft-refresh-secret") {
		t.Fatalf("provider credential leaked into link response: %s", completeRes.Body.String())
	}
	identity, err := repo.GetAuthIdentity("ms-fixture", microsoftFixtureAuth116("").Identity.Subject)
	if err != nil || identity.UserID != "admin" {
		t.Fatalf("Microsoft identity not linked to current user: %+v err=%v", identity, err)
	}
	credential, err := repo.GetProviderCredential("admin", "ms-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(credential.EncryptedRefreshToken, "microsoft-refresh-secret") {
		t.Fatal("provider credential stored in plaintext")
	}
	plain, err := api.decryptProviderCredential116(credential)
	if err != nil || plain != "microsoft-refresh-secret" {
		t.Fatalf("saved credential cannot be decrypted: %q err=%v", plain, err)
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/providers/ms-fixture/credential/refresh", nil)
	refreshReq.Header.Set("Authorization", "Bearer "+access)
	refreshRes := httptest.NewRecorder()
	handler.ServeHTTP(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusOK || strings.Contains(refreshRes.Body.String(), "microsoft-refresh-rotated") {
		t.Fatalf("credential refresh status=%d body=%s", refreshRes.Code, refreshRes.Body.String())
	}
	credential, err = repo.GetProviderCredential("admin", "ms-fixture")
	if err != nil {
		t.Fatal(err)
	}
	plain, err = api.decryptProviderCredential116(credential)
	if err != nil || plain != "microsoft-refresh-rotated" || credential.LastRefreshedAt.IsZero() {
		t.Fatalf("rotated credential mismatch plain=%q refreshedAt=%v err=%v", plain, credential.LastRefreshedAt, err)
	}
}

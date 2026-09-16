package httpapi

import (
	"context"
	"encoding/base64"
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

type oidcFixtureConnector115 struct{}

func (oidcFixtureConnector115) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "oidc-fixture", DisplayName: "OIDC Fixture", Version: "0.11.5", Capabilities: []authconnector.Capability{authconnector.CapabilityBrowserAuth, authconnector.CapabilityEmail}}
}
func (oidcFixtureConnector115) Health(context.Context) error { return nil }
func (oidcFixtureConnector115) DefaultRedirectURI() string {
	return "https://launcher.example.test/api/v1/auth/oidc/oidc-fixture/callback"
}
func (oidcFixtureConnector115) BeginBrowserAuth(ctx context.Context, req authconnector.BrowserAuthRequest) (authconnector.BrowserAuthStart, error) {
	u, _ := url.Parse("https://idp.example.test/authorize")
	q := u.Query()
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", req.PKCEChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return authconnector.BrowserAuthStart{AuthorizationURL: u.String(), State: req.State, ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
}
func (oidcFixtureConnector115) CompleteBrowserAuth(ctx context.Context, cb authconnector.BrowserAuthCallback) (authconnector.Authentication, error) {
	if cb.Code != "fixture-code" || len(cb.Nonce) < 32 || len(cb.PKCEVerifier) < 43 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "bad oidc callback")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "oidc-user-42", Email: "oidc@example.test", Username: "oidc", DisplayName: "OIDC User", Claims: map[string]any{"iss": "fixture"}}, AuthMethods: []string{"oidc"}}, nil
}

func TestOIDCBeginCompleteCreatesCanonicalNeverSession(t *testing.T) {
	cfg := config.Config{PublicURL: "https://launcher.example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-test"}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	core := federation.New(repo)
	if err := core.RegisterWithPolicy(oidcFixtureConnector115{}, federation.ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	handler := Server{Version: "0.11.5", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath), State: NewRuntimeState(), Federation: core}.Handler()
	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/oidc-fixture/begin", strings.NewReader(`{"deviceId":"desktop-1"}`))
	beginReq.Header.Set("Content-Type", "application/json")
	beginRes := httptest.NewRecorder()
	handler.ServeHTTP(beginRes, beginReq)
	if beginRes.Code != http.StatusOK {
		t.Fatalf("begin status=%d body=%s", beginRes.Code, beginRes.Body.String())
	}
	var begin struct {
		Data struct {
			AuthorizationURL string `json:"authorizationUrl"`
			State            string `json:"state"`
			Transaction      string `json:"transaction"`
		} `json:"data"`
	}
	if err := json.Unmarshal(beginRes.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	if begin.Data.Transaction == "" || begin.Data.State == "" {
		t.Fatalf("incomplete begin response: %s", beginRes.Body.String())
	}
	authURL, _ := url.Parse(begin.Data.AuthorizationURL)
	if authURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE S256 missing: %s", begin.Data.AuthorizationURL)
	}
	completeBody, _ := json.Marshal(map[string]any{"code": "fixture-code", "state": begin.Data.State, "transaction": begin.Data.Transaction})
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/oidc-fixture/complete", strings.NewReader(string(completeBody)))
	completeReq.Header.Set("Content-Type", "application/json")
	completeRes := httptest.NewRecorder()
	handler.ServeHTTP(completeRes, completeReq)
	if completeRes.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", completeRes.Code, completeRes.Body.String())
	}
	if !strings.Contains(completeRes.Body.String(), "accessToken") || !strings.Contains(completeRes.Body.String(), "refreshToken") {
		t.Fatalf("Never session tokens missing: %s", completeRes.Body.String())
	}
	identity, err := repo.GetAuthIdentity("oidc-fixture", "oidc-user-42")
	if err != nil || identity.UserID == "" {
		t.Fatalf("OIDC identity not persisted: %+v err=%v", identity, err)
	}
}

func TestOIDCTransactionTamperIsRejected(t *testing.T) {
	cfg := config.Config{AuthTokenSecret: "0123456789abcdef0123456789abcdef-test"}
	s := Server{Config: cfg}
	tx, err := s.sealOIDCTransaction115(oidcTransaction115{ProviderID: "p", RedirectURI: "https://x.example/cb", State: "s", Nonce: "n", PKCEVerifier: strings.Repeat("v", 43), ExpiresAt: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tx)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.openOIDCTransaction115(tampered); err == nil {
		t.Fatal("tampered transaction was accepted")
	}
}

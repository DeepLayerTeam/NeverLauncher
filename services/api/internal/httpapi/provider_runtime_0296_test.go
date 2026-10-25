package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type hostileFactorPassword0296 struct{}

func (hostileFactorPassword0296) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "parity-password", DisplayName: "Parity password", Version: "2", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (hostileFactorPassword0296) Health(context.Context) error { return nil }
func (hostileFactorPassword0296) AuthenticatePassword(_ context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if req.Secret != "correct" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "denied")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "subject-pwd", Issuer: "https://issuer.example.test"}, AuthMethods: []string{"password", "mfa", "passkey"}, ProviderToken: "external-secret"}, nil
}

type hostileFactorBrowser0296 struct{ oidcFixtureConnector115 }

func (hostileFactorBrowser0296) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "parity-browser", DisplayName: "Parity browser", Version: "2", Capabilities: []authconnector.Capability{authconnector.CapabilityBrowserAuth}}
}
func (hostileFactorBrowser0296) CompleteBrowserAuth(ctx context.Context, cb authconnector.BrowserAuthCallback) (authconnector.Authentication, error) {
	if _, err := (oidcFixtureConnector115{}).CompleteBrowserAuth(ctx, cb); err != nil {
		return authconnector.Authentication{}, err
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "subject-browser", Issuer: "https://idp.example.test"}, AuthMethods: []string{"oidc", "mfa", "webauthn"}, ProviderToken: "browser-refresh-secret"}, nil
}

func TestProviderRuntimeParity0296AdminPasswordCredentialAndMFA(t *testing.T) {
	repo := repository.NewMemoryRepository("https://launcher.example.test")
	if _, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "parity-password", Issuer: "https://issuer.example.test", Subject: "subject-pwd"}); err != nil {
		t.Fatal(err)
	}
	core := federation.New(repo)
	if err := core.Register(hostileFactorPassword0296{}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: "0123456789abcdef0123456789abcdef-parity", PublicURL: "https://launcher.example.test"}
	api := Server{Version: "0.29.6", Config: cfg, Repo: repo, State: NewRuntimeState(), Federation: core}
	if err := api.State.Passkeys.setPolicy("admin", mfaRequired117); err != nil {
		t.Fatal(err)
	}
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", strings.NewReader(`{"providerId":"parity-password","identifier":"admin","password":"correct"}`))
		out := httptest.NewRecorder()
		api.Handler().ServeHTTP(out, req)
		return out
	}
	if rr := request(); rr.Code != http.StatusUnauthorized {
		t.Fatalf("upstream MFA bypassed local policy: %d %s", rr.Code, rr.Body.String())
	}
	identity, err := repo.GetAuthIdentityByIssuer("parity-password", "https://issuer.example.test", "subject-pwd")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.GetProviderCredentialByIdentity("admin", identity.ID); err == nil {
		t.Fatal("provider token stored without Never MFA")
	}
	if err := api.State.Passkeys.setPolicy("admin", mfaOptional117); err != nil {
		t.Fatal(err)
	}
	ok := request()
	if ok.Code != http.StatusOK || strings.Contains(ok.Body.String(), "external-secret") {
		t.Fatalf("admin login or credential separation failed: %d %s", ok.Code, ok.Body.String())
	}
	var body struct {
		RefreshToken string `json:"refreshToken"`
		SessionID    string `json:"sessionId"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.RefreshToken == "" || body.SessionID == "" {
		t.Fatalf("missing Never session: %s", ok.Body.String())
	}
	record, err := repo.GetProviderCredentialByIdentity("admin", identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := api.decryptProviderCredential116(record)
	if err != nil || plain != "external-secret" {
		t.Fatalf("provider credential not persisted correctly: err=%v", err)
	}
	if rec, found := api.State.AuthSessions.get(body.SessionID, "admin"); !found || rec.AuthStrength != "single-factor" {
		t.Fatalf("bad session assurance: %+v %v", rec, found)
	}
}

func TestProviderRuntimeParity0296BrowserMFAHasNoPreApprovalCredential(t *testing.T) {
	cfg := config.Config{Environment: "test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), PublicURL: "https://launcher.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-parity"}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	if _, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "parity-browser", Issuer: "https://idp.example.test", Subject: "subject-browser"}); err != nil {
		t.Fatal(err)
	}
	core := federation.New(repo)
	if err := core.Register(hostileFactorBrowser0296{}); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.29.6", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath), State: NewRuntimeState(), Federation: core}
	if err := api.State.Passkeys.setPolicy("admin", mfaRequired117); err != nil {
		t.Fatal(err)
	}
	begin := httptest.NewRecorder()
	api.Handler().ServeHTTP(begin, httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/parity-browser/begin", strings.NewReader(`{"redirectUri":"https://launcher.example.test/api/v1/auth/oidc/parity-browser/callback"}`)))
	if begin.Code != http.StatusOK {
		t.Fatalf("browser begin failed: %d %s", begin.Code, begin.Body.String())
	}
	var initial struct {
		Data struct {
			State       string `json:"state"`
			Transaction string `json:"transaction"`
		} `json:"data"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"code": "fixture-code", "state": initial.Data.State, "transaction": initial.Data.Transaction})
	complete := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		api.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/parity-browser/complete", bytes.NewReader(payload)))
		return rr
	}
	if rr := complete(); rr.Code != http.StatusUnauthorized {
		t.Fatalf("browser upstream MFA bypassed local policy: %d %s", rr.Code, rr.Body.String())
	}
	identity, err := repo.GetAuthIdentityByIssuer("parity-browser", "https://idp.example.test", "subject-browser")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetProviderCredentialByIdentity("admin", identity.ID); err == nil {
		t.Fatal("refresh token was saved before MFA")
	}
	if len(api.State.AuthSessions.listByUser("admin")) != 0 {
		t.Fatal("browser login created Never session before MFA")
	}
	if err := api.State.Passkeys.setPolicy("admin", mfaOptional117); err != nil {
		t.Fatal(err)
	}
	ok := complete()
	if ok.Code != http.StatusOK || strings.Contains(ok.Body.String(), "browser-refresh-secret") {
		t.Fatalf("browser login failed: %d %s", ok.Code, ok.Body.String())
	}
	record, err := repo.GetProviderCredentialByIdentity("admin", identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := api.decryptProviderCredential116(record); err != nil || token != "browser-refresh-secret" {
		t.Fatalf("bad encrypted provider token err=%v", err)
	}
	if !strings.Contains(ok.Body.String(), `"issuer":"https://idp.example.test"`) {
		t.Fatalf("browser login did not expose canonical issuer: %s", ok.Body.String())
	}
}

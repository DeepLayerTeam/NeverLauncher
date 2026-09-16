package httpapi

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type federationMatrixPasswordConnector01110 struct{ id string }

func (c federationMatrixPasswordConnector01110) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: c.id, DisplayName: "Matrix " + c.id, Version: "0.11.10", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (c federationMatrixPasswordConnector01110) Health(context.Context) error { return nil }
func (c federationMatrixPasswordConnector01110) AuthenticatePassword(_ context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if req.Secret != "secret" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	return authconnector.Authentication{
		Identity:    authconnector.Identity{Subject: "subject-" + c.id, Email: c.id + "@matrix.invalid", Username: c.id, DisplayName: "Matrix " + c.id},
		AuthMethods: []string{c.id, "password"}, ProviderToken: "provider-token-" + c.id,
	}, nil
}

type federationMatrixBrowserConnector01110 struct{ id string }

func (c federationMatrixBrowserConnector01110) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: c.id, DisplayName: "Matrix " + c.id, Version: "0.11.10", Capabilities: []authconnector.Capability{authconnector.CapabilityBrowserAuth}}
}
func (c federationMatrixBrowserConnector01110) Health(context.Context) error { return nil }
func (c federationMatrixBrowserConnector01110) BeginBrowserAuth(_ context.Context, req authconnector.BrowserAuthRequest) (authconnector.BrowserAuthStart, error) {
	return authconnector.BrowserAuthStart{AuthorizationURL: "https://idp.invalid/authorize", State: req.State, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (c federationMatrixBrowserConnector01110) CompleteBrowserAuth(_ context.Context, cb authconnector.BrowserAuthCallback) (authconnector.Authentication, error) {
	if cb.Code != "code" || cb.State != "state" || cb.Nonce != "nonce" || cb.PKCEVerifier != "verifier" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid browser proof")
	}
	return authconnector.Authentication{
		Identity:    authconnector.Identity{Subject: "subject-" + c.id, Email: c.id + "@matrix.invalid", Username: c.id, DisplayName: "Matrix " + c.id},
		AuthMethods: []string{c.id}, ProviderToken: "provider-token-" + c.id,
	}, nil
}

func TestFederationE2E01110CanonicalSessionMatrix(t *testing.T) {
	repo := repository.NewMemoryRepository("https://api.example.test")
	core := federation.New(repo)
	for _, id := range []string{"sql", "http"} {
		if err := core.RegisterWithPolicy(federationMatrixPasswordConnector01110{id: id}, federation.ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"oidc", "microsoft"} {
		if err := core.RegisterWithPolicy(federationMatrixBrowserConnector01110{id: id}, federation.ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
			t.Fatal(err)
		}
	}
	state := NewRuntimeState()
	server := Server{
		Version: "0.11.10",
		Config:  config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-matrix"},
		Repo:    repo, State: state, Federation: core,
	}

	type scenario struct {
		id       string
		login    func() (federation.Result, error)
		methods  []string
		strength string
	}
	localUser, err := repo.GetUserByEmail("admin@neverlauncher.local")
	if err != nil {
		t.Fatal(err)
	}
	localIdentity, err := repo.GetAuthIdentity("local", localUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	localResult := federation.Result{Provider: authconnector.Metadata{ID: "local"}, Identity: localIdentity, User: localUser, AuthMethods: []string{"password"}}

	scenarios := []scenario{
		{id: "local", login: func() (federation.Result, error) { return localResult, nil }, methods: []string{"password"}, strength: "single-factor"},
		{id: "sql", login: func() (federation.Result, error) {
			return core.AuthenticatePassword(context.Background(), "sql", authconnector.PasswordRequest{Identifier: "sql", Secret: "secret"})
		}, methods: []string{"sql", "password"}, strength: "single-factor"},
		{id: "http", login: func() (federation.Result, error) {
			return core.AuthenticatePassword(context.Background(), "http", authconnector.PasswordRequest{Identifier: "http", Secret: "secret"})
		}, methods: []string{"http", "password"}, strength: "single-factor"},
		{id: "oidc", login: func() (federation.Result, error) {
			return core.CompleteBrowserAuth(context.Background(), "oidc", authconnector.BrowserAuthCallback{Code: "code", State: "state", Nonce: "nonce", PKCEVerifier: "verifier"})
		}, methods: []string{"oidc"}, strength: "single-factor"},
		{id: "microsoft", login: func() (federation.Result, error) {
			return core.CompleteBrowserAuth(context.Background(), "microsoft", authconnector.BrowserAuthCallback{Code: "code", State: "state", Nonce: "nonce", PKCEVerifier: "verifier"})
		}, methods: []string{"microsoft"}, strength: "single-factor"},
	}

	for _, tc := range scenarios {
		t.Run(tc.id, func(t *testing.T) {
			result, err := tc.login()
			if err != nil {
				t.Fatal(err)
			}
			if result.ProviderToken != "" && result.ProviderToken == server.Config.AuthTokenSecret {
				t.Fatal("provider token crossed Never token boundary")
			}
			req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
			session, refresh, err := state.AuthSessions.createWithAuth(result.User, req, "matrix-"+tc.id, tc.methods, tc.strength, time.Now().UTC(), result.Identity.ID, tc.id)
			if err != nil {
				t.Fatal(err)
			}
			access, err := server.issueAccessTokenForSession(result.User, session)
			if err != nil || access == "" || access == result.ProviderToken {
				t.Fatalf("Never access token boundary failed access=%q provider=%q err=%v", access, result.ProviderToken, err)
			}
			rotated, nextRefresh, err := state.AuthSessions.rotate(refresh)
			if err != nil || nextRefresh == "" || nextRefresh == refresh || rotated.ID != session.ID {
				t.Fatalf("refresh rotation failed rotated=%+v err=%v", rotated, err)
			}
			mc, mcToken, _, err := server.issueMinecraftSession119(result.User, session.ID, "matrix-client")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, gotUser, err := server.validateMinecraftToken119(mcToken); err != nil || gotUser.ID != result.User.ID {
				t.Fatalf("Minecraft session validation failed: user=%+v err=%v", gotUser, err)
			}
			if ok := state.AuthSessions.revoke(session.ID, "matrix-revoke"); !ok {
				t.Fatal("parent Never session was not revoked")
			}
			if _, _, _, err := server.validateMinecraftToken119(mcToken); err == nil {
				t.Fatalf("Minecraft token %s survived parent Never revoke", mc.ID)
			}
		})
	}

	// Passkey is a Never authentication method rather than an external connector;
	// it must nevertheless traverse the same session -> refresh -> Minecraft boundary.
	t.Run("passkey", func(t *testing.T) {
		user := model.User{ID: "user-passkey-matrix", Email: "passkey@matrix.invalid", DisplayName: "Passkey Matrix", RoleID: "player", Status: "active", ProjectRoles: map[string]string{}}
		if _, err := repo.SaveUser(user); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/api/v1/auth/webauthn/authenticate/complete", nil)
		session, refresh, err := state.AuthSessions.createWithAuth(user, req, "matrix-passkey", []string{"passkey"}, "phishing-resistant", time.Now().UTC(), "", "local")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.issueAccessTokenForSession(user, session); err != nil {
			t.Fatal(err)
		}
		if _, next, err := state.AuthSessions.rotate(refresh); err != nil || next == refresh {
			t.Fatalf("passkey session refresh failed next=%q err=%v", next, err)
		}
		_, token, _, err := server.issueMinecraftSession119(user, session.ID, "matrix-passkey")
		if err != nil {
			t.Fatal(err)
		}
		if ok := state.AuthSessions.revoke(session.ID, "matrix-revoke"); !ok {
			t.Fatal("parent Never session was not revoked")
		}
		if _, _, _, err := server.validateMinecraftToken119(token); err == nil {
			t.Fatal("passkey-derived Minecraft token survived parent revoke")
		}
	})

	if got := len(core.Providers()); got != 4 {
		t.Fatalf("expected four external matrix providers, got %d", got)
	}
	_ = fmt.Sprintf("%v", core.Health(context.Background()))
}

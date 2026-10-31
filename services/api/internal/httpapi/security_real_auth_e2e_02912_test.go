package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

// A real HTTP fixture with two issuers sharing both subject and email. The
// upstream returns a refresh secret which must NEVER appear in a Never token.
type dualIssuerConnector02912 struct{ calls *atomic.Int64 }

func (dualIssuerConnector02912) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "issuer-e2e", DisplayName: "Issuer isolation E2E", Version: "2.0.0", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (dualIssuerConnector02912) Health(context.Context) error { return nil }
func (c dualIssuerConnector02912) AuthenticatePassword(_ context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	c.calls.Add(1)
	if req.Identifier != "shared@example.test" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "unknown principal")
	}
	issuer := ""
	switch req.Secret {
	case "valid-password-issuer-a":
		issuer = "https://issuer-a.example.test"
	case "valid-password-issuer-b":
		issuer = "https://issuer-b.example.test"
	default:
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid password")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "same-subject", Issuer: issuer, Email: "shared@example.test"}, AuthMethods: []string{"password"}, ProviderToken: "upstream-secret-for-" + issuer}, nil
}

type authHTTPResult02912 struct {
	Data struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Identity struct {
			Issuer string `json:"issuer"`
		} `json:"identity"`
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
		Tokens struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
		} `json:"tokens"`
	} `json:"data"`
}

func securityHTTP02912(t *testing.T, client *http.Client, url, method, body, access string, expected int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if access != "" {
		req.Header.Set("Authorization", "Bearer "+access)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != expected {
		t.Fatalf("%s %s => %d (want %d): %s", method, url, resp.StatusCode, expected, string(data))
	}
	return data
}

func TestSecurityRealAuthHTTP02912(t *testing.T) {
	repo := repository.NewMemoryRepository("https://api.example.test")
	for _, item := range []struct{ user, issuer string }{
		{"issuer-user-a", "https://issuer-a.example.test"},
		{"issuer-user-b", "https://issuer-b.example.test"},
	} {
		if _, err := repo.SaveUser(model.User{ID: item.user, Email: item.user + "@example.test", RoleID: "player", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: item.user, Provider: "issuer-e2e", Issuer: item.issuer, Subject: "same-subject", Email: "shared@example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	calls := &atomic.Int64{}
	core := federation.New(repo)
	if err := core.Register(dualIssuerConnector02912{calls: calls}); err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(federation.RoutingConfig{Version: 1, DefaultProvider: "issuer-e2e", Rules: []federation.RoutingRule{{EmailDomain: "example.test", ProviderID: "issuer-e2e", Strict: true}}}); err != nil {
		t.Fatal(err)
	}
	api := Server{Version: "0.29.12", Config: config.Config{Environment: "test", RepositoryDriver: "memory", PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-security-e2e"}, Repo: repo, State: NewRuntimeState(), Federation: core}
	httpServer := httptest.NewServer(api.Handler())
	defer httpServer.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	base := httpServer.URL
	before := calls.Load()
	for _, body := range []string{
		`{"providerId":"issuer-e2e","providerId":"local","identifier":"shared@example.test","password":"valid-password-issuer-a"}`,
		`{"providerId":"issuer-e2e","ProviderId":"local","identifier":"shared@example.test","password":"valid-password-issuer-a"}`,
		`{"providerId":"issuer-e2e","identifier":"shared@example.test","password":"valid-password-issuer-a"}{"providerId":"local"}`,
		`{"providerId":"issuer-e2e","identifier":"shared@example.test","password":"valid-password-issuer-a","unknown":true}`,
	} {
		securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, body, "", http.StatusBadRequest)
	}
	if calls.Load() != before {
		t.Fatal("ambiguous credentials reached upstream auth provider")
	}
	securityHTTP02912(t, client, base+"/api/v1/admin/login", http.MethodPost, `{"providerId":"issuer-e2e","providerId":"local"}`, "", http.StatusBadRequest)
	securityHTTP02912(t, client, base+"/api/v1/auth/refresh", http.MethodPost, `{"refreshToken":"a","refreshToken":"b"}`, "", http.StatusBadRequest)
	securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, `{"password":"`+strings.Repeat("x", 16*1024)+`"}`, "", http.StatusRequestEntityTooLarge)
	securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, `{"identifier":"shared@example.test","password":"incorrect"}`, "", http.StatusUnauthorized)
	securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, `{"providerId":"local","identifier":"shared@example.test","password":"valid-password-issuer-a"}`, "", http.StatusForbidden)
	login := func(password string) authHTTPResult02912 {
		t.Helper()
		body := fmt.Sprintf(`{"identifier":"shared@example.test","password":%q}`, password)
		data := securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, body, "", http.StatusOK)
		if bytes.Contains(data, []byte("upstream-secret")) {
			t.Fatal("upstream credential leaked through Never login")
		}
		var response authHTTPResult02912
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		if response.Data.Tokens.RefreshToken == "" || response.Data.Tokens.AccessToken == "" || response.Data.Session.ID == "" {
			t.Fatalf("missing tokens: %s", data)
		}
		return response
	}
	a := login("valid-password-issuer-a")
	b := login("valid-password-issuer-b")
	if a.Data.User.ID != "issuer-user-a" || b.Data.User.ID != "issuer-user-b" || a.Data.Identity.Issuer == b.Data.Identity.Issuer {
		t.Fatalf("issuer isolation failed: %+v %+v", a.Data, b.Data)
	}
	refresh := func(token string, expected int) []byte {
		return securityHTTP02912(t, client, base+"/api/v1/auth/refresh", http.MethodPost, fmt.Sprintf(`{"refreshToken":%q}`, token), "", expected)
	}
	var rotated authHTTPResult02912
	if err := json.Unmarshal(refresh(a.Data.Tokens.RefreshToken, http.StatusOK), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Data.Tokens.RefreshToken == "" || rotated.Data.Tokens.RefreshToken == a.Data.Tokens.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	refresh(a.Data.Tokens.RefreshToken, http.StatusUnauthorized)
	securityHTTP02912(t, client, base+"/api/v1/auth/sessions", http.MethodGet, "", rotated.Data.Tokens.AccessToken, http.StatusUnauthorized)
	securityHTTP02912(t, client, base+"/api/v1/auth/sessions", http.MethodGet, "", b.Data.Tokens.AccessToken, http.StatusOK)
	if err := repo.SetProtectionBan(context.Background(), repository.ProtectionBan{UserID: "issuer-user-b", Reason: "real e2e security gate", Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	refresh(b.Data.Tokens.RefreshToken, http.StatusForbidden)
	securityHTTP02912(t, client, base+"/api/v1/auth/login", http.MethodPost, `{"identifier":"shared@example.test","password":"valid-password-issuer-b"}`, "", http.StatusForbidden)
	if _, err := repo.RevokeProtectionBan(context.Background(), "issuer-user-b", "tester"); err != nil {
		t.Fatal(err)
	}
	_ = login("valid-password-issuer-b")
	refresh(b.Data.Tokens.RefreshToken, http.StatusUnauthorized)
}

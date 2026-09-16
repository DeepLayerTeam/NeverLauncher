package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestAccessToken118IsJWTAndSupportsKeyRotation(t *testing.T) {
	state := NewRuntimeState()
	s := Server{Repo: repository.NewMemoryRepository("https://api.example.test"), Config: config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "fallback-secret", AuthTokenIssuer: "https://issuer.example.test", AuthTokenAudience: "neverlauncher-api", AuthTokenActiveKID: "old", AuthTokenKeysJSON: `{"old":"0123456789abcdef0123456789abcdef-old","new":"0123456789abcdef0123456789abcdef-new"}`}, State: state}
	user := model.User{ID: "user-1", Email: "u@example.test", RoleID: "owner"}
	req := httptest.NewRequest("POST", "https://api.example.test/login", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("User-Agent", "NeverLauncher-Test/1")
	session, _, err := state.AuthSessions.createWithAuth(user, req, "Desktop", []string{"password", "passkey"}, "phishing-resistant", time.Now().UTC(), "identity-local-user-1", "local")
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.issueAccessTokenForSession(user, session)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", token)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header authTokenHeader118
	if json.Unmarshal(raw, &header) != nil || header.Kid != "old" || header.Alg != "HS256" {
		t.Fatalf("bad JWT header: %s", raw)
	}
	claims, err := s.verifyAdminToken(token)
	if err != nil || claims.Iss != "https://issuer.example.test" || claims.Aud != "neverlauncher-api" || claims.JTI == "" {
		t.Fatalf("bad claims: %#v err=%v", claims, err)
	}
	s.Config.AuthTokenActiveKID = "new"
	if _, err := s.verifyAdminToken(token); err != nil {
		t.Fatalf("old token must verify while old key remains in keyring: %v", err)
	}
	newToken, err := s.issueAccessTokenForSession(user, session)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = base64.RawURLEncoding.DecodeString(strings.Split(newToken, ".")[0])
	_ = json.Unmarshal(raw, &header)
	if header.Kid != "new" {
		t.Fatalf("new active kid not used: %#v", header)
	}
}

func TestSessionManagement118RiskRenameAndProviderRevoke(t *testing.T) {
	store := newAuthSessionStore111()
	user := model.User{ID: "user-1", Email: "u@example.test", RoleID: "owner"}
	req := httptest.NewRequest("POST", "http://example.test", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("User-Agent", "UA/1")
	first, _, err := store.createWithAuth(user, req, "device-a", []string{"oidc"}, "single-factor", time.Now().UTC(), "id-1", "oidc-main")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.createWithAuth(user, req, "device-b", []string{"password"}, "single-factor", time.Now().UTC(), "id-2", "local")
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := store.renameDevice118(first.ID, user.ID, "Work Laptop")
	if err != nil || renamed.Device != "Work Laptop" || renamed.DeviceID != "device-a" {
		t.Fatalf("rename failed: %#v %v", renamed, err)
	}
	changed := httptest.NewRequest("GET", "http://example.test", nil)
	changed.RemoteAddr = "203.0.113.44:5555"
	changed.Header.Set("User-Agent", "UA/2")
	observed, ok := store.observe(first.ID, user.ID, changed)
	if !ok || observed.RiskState != "elevated" || len(observed.RiskReasons) != 2 {
		t.Fatalf("risk not elevated: %#v", observed)
	}
	if got := store.revokeFiltered118("", "oidc-main", "", "compromised-provider:oidc-main"); got != 1 {
		t.Fatalf("provider revoke=%d", got)
	}
	items := store.listByUser(user.ID)
	var compromised bool
	for _, it := range items {
		if it.ID == first.ID {
			compromised = it.Status == "revoked" && it.RiskState == "compromised"
		}
	}
	if !compromised {
		t.Fatalf("provider session not marked compromised: %#v", items)
	}
	if _, ok := store.get(second.ID, user.ID); !ok {
		t.Fatal("unrelated local session must stay active")
	}
}

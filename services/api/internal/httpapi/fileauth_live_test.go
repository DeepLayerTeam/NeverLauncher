package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

// The real federated login route must use the live file, not a nominal
// registration test or the one-time imported Never local password.
func TestLiveFileAuthFederatedLogin0426(t *testing.T) {
	db := filepath.Join(t.TempDir(), "Database.json")
	secret := "live-legacy-password-426"
	sum := sha256.Sum256([]byte(secret))
	uuid := "37a144c1-263e-4e9b-820f-917640f95b2d"
	data := fmt.Sprintf(`{"%s":{"username":"Player_426","uuid":"%s","password":"%s","permissions":{"roles":["ADMIN"]}}}`, uuid, uuid, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(db, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: "live-file-auth-federation-test-secret-426",
		AuthFileProvidersJSON: fmt.Sprintf(`[{"id":"gravit-live","databasePath":%q,"passwordFormat":"sha256-hex","provisioning":{"mode":"jit","defaultRole":"player"}}]`, db),
	}
	repo := repository.NewMemoryRepository("http://example.test")
	core, err := NewFederationCore(context.Background(), repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	first, err := core.AuthenticatePassword(context.Background(), "gravit-live", authconnector.PasswordRequest{Identifier: "Player_426", Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity.Subject != uuid || first.User.RoleID != "player" || first.Identity.Claims["minecraftUuid"] != uuid {
		t.Fatalf("identity/role/UUID mismatch %+v", first)
	}
	if second, err := core.AuthenticatePassword(context.Background(), "gravit-live", authconnector.PasswordRequest{Identifier: "Player_426", Secret: secret}); err != nil || second.User.ID != first.User.ID {
		t.Fatalf("unstable identity %v %v", second, err)
	}
	api := Server{Version: "0.42.6", Config: cfg, Repo: repo, State: NewRuntimeState(), Federation: core}
	login := func(password string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"identifier":"Player_426","password":%q,"providerId":"gravit-live"}`, password)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		api.Handler().ServeHTTP(res, req)
		return res
	}
	if res := login(secret); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"provider":"gravit-live"`) || strings.Contains(res.Body.String(), secret) {
		t.Fatalf("live login: %d %s", res.Code, res.Body.String())
	}
	if err := os.Remove(db); err != nil {
		t.Fatal(err)
	}
	if res := login(secret); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing file permitted cached login: %d %s", res.Code, res.Body.String())
	}
}

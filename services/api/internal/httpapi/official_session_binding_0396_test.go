package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

// A real authenticated HTTP handler must return its verified JWT SID, not
// an attacker-controlled session identifier supplied by the Desktop renderer.
func TestOfficialBrowserConfigBindsNeverVaultSession0396(t *testing.T) {
	cfg := config.Config{
		PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local",
		StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test",
		AuthTokenSecret: "test-secret-for-integration", AuthTokenTTLHours: 1,
		WebAuthnRPID: "example.test", WebAuthnRPName: "NeverLauncher Test",
		WebAuthnOrigins:            []string{"http://example.test"},
		MinecraftMicrosoftClientID: "01234567-89ab-cdef-0123-456789abcdef",
	}
	api := Server{Version: "0.39.6-test", Config: cfg,
		Repo:    repository.NewMemoryRepository(cfg.PublicURL),
		Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}.Handler()
	unauth := request0211(t, api, http.MethodGet, "/api/v1/minecraft/official/browser/config", "", "")
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous config returned %d", unauth.Code)
	}
	token := loginAdmin(t, api)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("access bearer is not a JWT")
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub string `json:"sub"`
		SID string `json:"sid"`
	}
	if err = json.Unmarshal(claimsRaw, &claims); err != nil || claims.Sub == "" || claims.SID == "" {
		t.Fatalf("invalid test JWT claims: %v", err)
	}
	response := request0211(t, api, http.MethodGet, "/api/v1/minecraft/official/browser/config", token, "")
	if response.Code != http.StatusOK {
		t.Fatalf("verified config: %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("identity proof must not be cached")
	}
	var result struct {
		Data struct {
			NeverSessionID string `json:"neverSessionId"`
			NeverUserID    string `json:"neverUserId"`
		} `json:"data"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.NeverSessionID != claims.SID || result.Data.NeverUserID != claims.Sub {
		t.Fatalf("backend identity proof differs from the authenticated claims")
	}
}

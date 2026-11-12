package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Настоящий авторизованный HTTP-обработчик должен возвращать проверенный SID JWT,
// а не заданный злоумышленником идентификатор сеанса из renderer Desktop.
func TestOfficialBrowserConfigBindsLauncherVaultSession0396(t *testing.T) {
	cfg := config.Config{
		PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local",
		StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test",
		AuthTokenSecret: "test-secret-for-integration", AuthTokenTTLHours: 1,
		WebAuthnRPID: "example.test", WebAuthnRPName: "Launcher Test",
		WebAuthnOrigins:            []string{"http://example.test"},
		MinecraftMicrosoftClientID: "01234567-89ab-cdef-0123-456789abcdef",
	}
	api := Server{Version: "0.39.6-test", Config: cfg,
		Repo:    repository.NewMemoryRepository(cfg.PublicURL),
		Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}.Handler()
	unauth := request0211(t, api, http.MethodGet, "/api/v1/minecraft/official/browser/config", "", "")
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("Конфигурация анонимного доступа вернула %d", unauth.Code)
	}
	token := loginAdmin(t, api)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Токен доступа Bearer не является JWT")
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
		t.Fatalf("Некорректные поля тестового JWT: %v", err)
	}
	response := request0211(t, api, http.MethodGet, "/api/v1/minecraft/official/browser/config", token, "")
	if response.Code != http.StatusOK {
		t.Fatalf("проверенная конфигурация: %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Подтверждение личности нельзя кешировать")
	}
	var result struct {
		Data struct {
			LauncherSessionID string `json:"launcherSessionId"`
			LauncherUserID    string `json:"launcherUserId"`
		} `json:"data"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.LauncherSessionID != claims.SID || result.Data.LauncherUserID != claims.Sub {
		t.Fatalf("Подтверждение личности сервером отличается от подтверждённых утверждений")
	}
}

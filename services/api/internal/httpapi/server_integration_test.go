package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func testServer(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Config{
		HTTPAddr:           "127.0.0.1:0",
		PublicURL:          "http://example.test",
		RepositoryDriver:   "memory",
		StorageDriver:      "local",
		StorageLocalPath:   t.TempDir(),
		BackupRoot:         t.TempDir(),
		CORSAllowedOrigins: []string{"http://example.test"},
		Environment:        "test",
		AuthTokenSecret:    "test-secret-for-integration",
		AuthTokenTTLHours:  1,
		MetricsEnabled:     true,
	}
	store := storage.NewLocalStorage(cfg.StorageLocalPath)
	if _, _, err := store.Save("demo-project", "demo-project-vanilla-3.4.0", "README.txt", strings.NewReader("")); err != nil {
		t.Fatalf("не удалось подготовить storage fixture: %v", err)
	}
	return Server{Version: "2.2.0-test", Config: cfg, Repo: repository.NewMemoryRepository(cfg.PublicURL), Storage: store}.Handler()
}

func TestHealthAndPublicManifest(t *testing.T) {
	handler := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("/health вернул статус %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "2.2.0-test") {
		t.Fatalf("/health не содержит версию: %s", res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/demo-project/profiles/vanilla/manifest?channel=stable", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("manifest endpoint вернул статус %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "demo-project") {
		t.Fatalf("manifest endpoint вернул неожиданный ответ: %s", res.Body.String())
	}
}

func TestAdminAuthAndStorageHealth(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/storage/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("storage health вернул статус %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "local") {
		t.Fatalf("storage health не содержит драйвер local: %s", res.Body.String())
	}
}

func TestAdminVersionUploadPublishFlow(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)

	versionBody := strings.NewReader(`{"profileId":"vanilla","channel":"stable","version":"2.2.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects/demo-project/versions", versionBody)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("создание версии вернуло статус %d: %s", res.Code, res.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("не удалось прочитать созданную версию: id=%q err=%v body=%s", created.ID, err, res.Body.String())
	}

	var payload bytes.Buffer
	writer := multipart.NewWriter(&payload)
	if err := writer.WriteField("path", "mods/example.jar"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", "example.jar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "jar-bytes"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects/demo-project/versions/"+created.ID+"/files", &payload)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("загрузка файла вернула статус %d: %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects/demo-project/versions/"+created.ID+"/publish", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("публикация версии вернула статус %d: %s", res.Code, res.Body.String())
	}
}

func loginAdmin(t *testing.T, handler http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("login вернул статус %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil || payload.Token == "" {
		t.Fatalf("не удалось получить token: token=%q err=%v body=%s", payload.Token, err, res.Body.String())
	}
	return payload.Token
}

func TestCanonicalStatusReadyAndMetrics(t *testing.T) {
	handler := testServer(t)

	for _, path := range []string{"/api/v1/status", "/api/v1/projects", "/ready", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s вернул статус %d: %s", path, res.Code, res.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/demo-project/profiles/vanilla/manifest?channel=stable", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "\"projectId\":\"demo-project\"") {
		t.Fatalf("v1 manifest вернул неожиданный ответ: %d %s", res.Code, res.Body.String())
	}
}

func TestAdminUsersSessionsAndRBAC(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "admin@neverlauncher.local") {
		t.Fatalf("/admin/me вернул неожиданный ответ: %d %s", res.Code, res.Body.String())
	}

	body := strings.NewReader(`{"email":"dev@example.ru","displayName":"Разработчик","roleId":"developer","password":"password-123","projectRoles":{"demo-project":"developer"}}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), "dev@example.ru") {
		t.Fatalf("создание пользователя вернуло неожиданный ответ: %d %s", res.Code, res.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("не удалось прочитать созданного пользователя: %v %s", err, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+created.ID+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "disabled") {
		t.Fatalf("disable пользователя вернул неожиданный ответ: %d %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("logout вернул статус %d: %s", res.Code, res.Body.String())
	}
}

func TestCanonicalAuthSessionEnforcement(t *testing.T) {
	handler := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/accounts", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("/api/v1/auth/accounts без токена должен вернуть 401, получено %d: %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin","deviceId":"integration-test"}`))
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("v1 login вернул статус %d: %s", res.Code, res.Body.String())
	}
	var loginPayload struct {
		Data struct {
			Session struct {
				ID string `json:"id"`
			} `json:"session"`
			Tokens struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &loginPayload); err != nil || loginPayload.Data.Tokens.AccessToken == "" || loginPayload.Data.Tokens.RefreshToken == "" || loginPayload.Data.Session.ID == "" {
		t.Fatalf("v1 login не вернул session/access/refresh: err=%v body=%s", err, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+loginPayload.Data.Tokens.AccessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "accounts-enforced") {
		t.Fatalf("/api/v1/auth/accounts с токеном вернул неожиданный ответ %d: %s", res.Code, res.Body.String())
	}

	refreshBody := `{"refreshToken":"` + loginPayload.Data.Tokens.RefreshToken + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("v1 refresh вернул статус %d: %s", res.Code, res.Body.String())
	}
	var refreshPayload struct {
		Data struct {
			Tokens struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &refreshPayload); err != nil || refreshPayload.Data.Tokens.AccessToken == "" || refreshPayload.Data.Tokens.RefreshToken == "" {
		t.Fatalf("v1 refresh не вернул новые токены: err=%v body=%s", err, res.Body.String())
	}
	if refreshPayload.Data.Tokens.RefreshToken == loginPayload.Data.Tokens.RefreshToken {
		t.Fatalf("refresh token не был ротирован")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+refreshPayload.Data.Tokens.AccessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "logged-out") {
		t.Fatalf("v1 logout вернул неожиданный ответ %d: %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+refreshPayload.Data.Tokens.AccessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("отозванная сессия должна отклоняться, получено %d: %s", res.Code, res.Body.String())
	}
}

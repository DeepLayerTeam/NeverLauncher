package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func decodeMap119(t *testing.T, body *bytes.Buffer) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(body.Bytes(), &v); err != nil {
		t.Fatalf("Ошибка разбора: %v тело ответа=%s", err, body.String())
	}
	return v
}

func TestMinecraftAuth119LauncherSessionExchangeJoinAndParentRevoke(t *testing.T) {
	handler := testServer(t)
	launcherToken, _ := deviceTrustLogin0121(t, handler, "mc-e2e")
	launcherToken = bindAccessToken0127(t, handler, launcherToken, "Minecraft e2e device").Access

	ex := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{"clientToken":"desktop-client"}`))
	ex.Header.Set("Authorization", "Bearer "+launcherToken)
	ex.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(ex)
	er := httptest.NewRecorder()
	handler.ServeHTTP(er, ex)
	if er.Code != http.StatusCreated {
		t.Fatalf("Обмен=%d %s", er.Code, er.Body.String())
	}
	ep := decodeMap119(t, er.Body)
	ed := ep["data"].(map[string]any)
	mcToken := ed["accessToken"].(string)
	profile := ed["profile"].(map[string]any)
	uuid := profile["id"].(string)
	username := profile["name"].(string)

	vr := httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+mcToken+`","clientToken":"desktop-client"}`))
	vv := httptest.NewRecorder()
	handler.ServeHTTP(vv, vr)
	if vv.Code != http.StatusNoContent {
		t.Fatalf("Проверка=%d %s", vv.Code, vv.Body.String())
	}

	joinBody, _ := json.Marshal(map[string]string{"accessToken": mcToken, "selectedProfile": uuid, "serverId": "server-hash-119"})
	jr := httptest.NewRequest(http.MethodPost, "/sessionserver/session/minecraft/join", bytes.NewReader(joinBody))
	jv := httptest.NewRecorder()
	handler.ServeHTTP(jv, jr)
	if jv.Code != http.StatusNoContent {
		t.Fatalf("Присоединение=%d %s", jv.Code, jv.Body.String())
	}
	wrongIP := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username="+username+"&serverId=server-hash-119&ip=203.0.113.250", nil)
	wrongIPV := httptest.NewRecorder()
	handler.ServeHTTP(wrongIPV, wrongIP)
	if wrongIPV.Code != http.StatusNoContent {
		t.Fatalf("hasJoined должен отклонять несовпадающий необязательный IP: %d %s", wrongIPV.Code, wrongIPV.Body.String())
	}
	// Репозиторий PostgreSQL погашает билет одним условным UPDATE; репозиторий в памяти
	// выполняет тот же атомарный контракт однократного использования под блокировкой.
	// Проверяйте конкурирующие HTTP-запросы, а не только последовательный повтор, чтобы
	// обнаруживать регрессию порядка чтения и погашения.
	const concurrentJoins = 12
	start := make(chan struct{})
	var joined sync.WaitGroup
	joined.Add(concurrentJoins)
	statuses := make(chan int, concurrentJoins)
	for i := 0; i < concurrentJoins; i++ {
		go func() {
			defer joined.Done()
			<-start
			hr := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username="+username+"&serverId=server-hash-119", nil)
			hv := httptest.NewRecorder()
			handler.ServeHTTP(hv, hr)
			if hv.Code == http.StatusOK && !strings.Contains(hv.Body.String(), uuid) {
				statuses <- http.StatusInternalServerError
				return
			}
			statuses <- hv.Code
		}()
	}
	close(start)
	joined.Wait()
	close(statuses)
	allowed, denied := 0, 0
	for code := range statuses {
		switch code {
		case http.StatusOK:
			allowed++
		case http.StatusNoContent:
			denied++
		default:
			t.Fatalf("Неожиданный статус параллельного /hasJoined: %d", code)
		}
	}
	if allowed != 1 || denied != concurrentJoins-1 {
		t.Fatalf("Только первый параллельный запрос /hasJoined может завершиться успешно: разрешено=%d отказано=%d", allowed, denied)
	}
	replay := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username="+username+"&serverId=server-hash-119", nil)
	replayV := httptest.NewRecorder()
	handler.ServeHTTP(replayV, replay)
	if replayV.Code != http.StatusNoContent {
		t.Fatalf("Повтор одноразового присоединения Yggdrasil должен отклоняться: %d %s", replayV.Code, replayV.Body.String())
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.Header.Set("Authorization", "Bearer "+launcherToken)
	lo := httptest.NewRecorder()
	handler.ServeHTTP(lo, logout)
	if lo.Code != http.StatusOK {
		t.Fatalf("Выход=%d %s", lo.Code, lo.Body.String())
	}
	vr = httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+mcToken+`"}`))
	vv = httptest.NewRecorder()
	handler.ServeHTTP(vv, vr)
	if vv.Code != http.StatusForbidden {
		t.Fatalf("Токен Minecraft должен прекращать действие вместе с основной сессией Launcher: %d %s", vv.Code, vv.Body.String())
	}
}

func TestMinecraftAuth119YggdrasilPasswordUsesFederationCore(t *testing.T) {
	handler := testServer(t)
	body := `{"username":"admin@launcher.local","password":"admin","clientToken":"legacy-client","requestUser":true}`
	r := httptest.NewRequest(http.MethodPost, "/authserver/authenticate", strings.NewReader(body))
	v := httptest.NewRecorder()
	handler.ServeHTTP(v, r)
	if v.Code != http.StatusOK {
		t.Fatalf("Аутентификация=%d %s", v.Code, v.Body.String())
	}
	p := decodeMap119(t, v.Body)
	token, ok := p["accessToken"].(string)
	if !ok || !strings.HasPrefix(token, "nlmc_") {
		t.Fatalf("Ожидался непрозрачный токен Minecraft: %#v", p["accessToken"])
	}
	vr := httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+token+`","clientToken":"legacy-client"}`))
	vv := httptest.NewRecorder()
	handler.ServeHTTP(vv, vr)
	if vv.Code != http.StatusNoContent {
		t.Fatalf("Проверка=%d %s", vv.Code, vv.Body.String())
	}
}

func TestMinecraftAuth119RefreshConsumesOldToken(t *testing.T) {
	handler := testServer(t)
	auth := httptest.NewRequest(http.MethodPost, "/authserver/authenticate", strings.NewReader(`{"username":"admin@launcher.local","password":"admin","clientToken":"refresh-client"}`))
	av := httptest.NewRecorder()
	handler.ServeHTTP(av, auth)
	if av.Code != http.StatusOK {
		t.Fatalf("Аутентификация=%d %s", av.Code, av.Body.String())
	}
	p := decodeMap119(t, av.Body)
	oldToken := p["accessToken"].(string)
	body := `{"accessToken":"` + oldToken + `","clientToken":"refresh-client"}`
	first := httptest.NewRequest(http.MethodPost, "/authserver/refresh", strings.NewReader(body))
	fv := httptest.NewRecorder()
	handler.ServeHTTP(fv, first)
	if fv.Code != http.StatusOK {
		t.Fatalf("Первое обновление=%d %s", fv.Code, fv.Body.String())
	}
	second := httptest.NewRequest(http.MethodPost, "/authserver/refresh", strings.NewReader(body))
	sv := httptest.NewRecorder()
	handler.ServeHTTP(sv, second)
	if sv.Code != http.StatusForbidden {
		t.Fatalf("Повторно использованный токен обновления должен отклоняться: %d %s", sv.Code, sv.Body.String())
	}
}

func TestMinecraftAuth119PlayerRoleCanExchangeSession(t *testing.T) {
	cfg := config.Config{PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "test-secret-player-119", WebAuthnRPID: "example.test", WebAuthnRPName: "Launcher Test", WebAuthnOrigins: []string{"http://example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	user, err := repo.SaveUser(model.User{Email: "player@example.test", DisplayName: "Player119", RoleID: "player", Status: "active", PasswordHash: hashPassword("player-password")})
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Version: "0.11.9-test", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}.Handler()
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"player@example.test","password":"player-password"}`))
	login.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(login)
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, login)
	if lr.Code != http.StatusOK {
		t.Fatalf("Вход игрока=%d %s пользователь=%s", lr.Code, lr.Body.String(), user.ID)
	}
	p := decodeMap119(t, lr.Body)
	token := p["data"].(map[string]any)["tokens"].(map[string]any)["accessToken"].(string)
	token = bindAccessToken0127(t, h, token, "Player Minecraft device").Access
	ex := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{}`))
	ex.Header.Set("Authorization", "Bearer "+token)
	setDeviceTrustClientMeta0127(ex)
	er := httptest.NewRecorder()
	h.ServeHTTP(er, ex)
	if er.Code != http.StatusCreated {
		t.Fatalf("Обмен токена игрока=%d %s", er.Code, er.Body.String())
	}
}

func TestMinecraftAuth119ExchangeRejectsMalformedJSON(t *testing.T) {
	handler := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@launcher.local","password":"admin"}`))
	login.Header.Set("Content-Type", "application/json")
	lr := httptest.NewRecorder()
	handler.ServeHTTP(lr, login)
	if lr.Code != http.StatusOK {
		t.Fatalf("Вход=%d %s", lr.Code, lr.Body.String())
	}
	p := decodeMap119(t, lr.Body)
	token := p["data"].(map[string]any)["tokens"].(map[string]any)["accessToken"].(string)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{"clientToken":`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	v := httptest.NewRecorder()
	handler.ServeHTTP(v, r)
	if v.Code != http.StatusBadRequest {
		t.Fatalf("Некорректные данные обмена=%d %s", v.Code, v.Body.String())
	}
}

func TestMinecraftProfile119StableAcrossEmailChange(t *testing.T) {
	cfg := config.Config{PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "test-secret-profile-119", WebAuthnRPID: "example.test", WebAuthnRPName: "Launcher Test", WebAuthnOrigins: []string{"http://example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	user, err := repo.SaveUser(model.User{Email: "first@example.test", DisplayName: "Stable119", RoleID: "player", Status: "active", PasswordHash: hashPassword("pw")})
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{Version: "0.11.9-test", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}
	first, err := srv.ensureMinecraftProfile119(user)
	if err != nil {
		t.Fatal(err)
	}
	user.Email = "changed@example.test"
	user.DisplayName = "ChangedName"
	user, err = repo.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}
	second, err := srv.ensureMinecraftProfile119(user)
	if err != nil {
		t.Fatal(err)
	}
	if first.UUID != second.UUID || first.Name != second.Name {
		t.Fatalf("Профиль должен оставаться неизменным: до=%+v после=%+v", first, second)
	}
}

func TestYggdrasilMetadata119RootIsExact(t *testing.T) {
	h := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	v := httptest.NewRecorder()
	h.ServeHTTP(v, r)
	if v.Code != http.StatusOK || !strings.Contains(v.Body.String(), "Launcher") {
		t.Fatalf("Корневые метаданные=%d %s", v.Code, v.Body.String())
	}
	metadata := decodeMap119(t, v.Body)
	meta, ok := metadata["meta"].(map[string]any)
	if !ok || meta["feature.non_email_login"] != true || meta["links"] == nil {
		t.Fatalf("Некорректные метаданные authlib-injector: %#v", metadata)
	}
	if _, legacyTopLevel := metadata["feature"]; legacyTopLevel {
		t.Fatalf("Флаги возможностей должны находиться внутри meta: %#v", metadata)
	}
	r = httptest.NewRequest(http.MethodGet, "/removed-legacy-path", nil)
	v = httptest.NewRecorder()
	h.ServeHTTP(v, r)
	if v.Code != http.StatusNotFound {
		t.Fatalf("Корневой обработчик не должен скрывать неизвестные пути: %d", v.Code)
	}
}

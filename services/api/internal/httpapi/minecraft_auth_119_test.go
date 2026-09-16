package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func decodeMap119(t *testing.T, body *bytes.Buffer) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v body=%s", err, body.String())
	}
	return v
}

func TestMinecraftAuth119NeverSessionExchangeJoinAndParentRevoke(t *testing.T) {
	handler := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin","deviceId":"mc-e2e"}`))
	login.Header.Set("Content-Type", "application/json")
	lr := httptest.NewRecorder()
	handler.ServeHTTP(lr, login)
	if lr.Code != http.StatusOK {
		t.Fatalf("login=%d %s", lr.Code, lr.Body.String())
	}
	payload := decodeMap119(t, lr.Body)
	data := payload["data"].(map[string]any)
	tokens := data["tokens"].(map[string]any)
	neverToken := tokens["accessToken"].(string)

	ex := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{"clientToken":"desktop-client"}`))
	ex.Header.Set("Authorization", "Bearer "+neverToken)
	ex.Header.Set("Content-Type", "application/json")
	er := httptest.NewRecorder()
	handler.ServeHTTP(er, ex)
	if er.Code != http.StatusCreated {
		t.Fatalf("exchange=%d %s", er.Code, er.Body.String())
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
		t.Fatalf("validate=%d %s", vv.Code, vv.Body.String())
	}

	joinBody, _ := json.Marshal(map[string]string{"accessToken": mcToken, "selectedProfile": uuid, "serverId": "server-hash-119"})
	jr := httptest.NewRequest(http.MethodPost, "/sessionserver/session/minecraft/join", bytes.NewReader(joinBody))
	jv := httptest.NewRecorder()
	handler.ServeHTTP(jv, jr)
	if jv.Code != http.StatusNoContent {
		t.Fatalf("join=%d %s", jv.Code, jv.Body.String())
	}
	wrongIP := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username="+username+"&serverId=server-hash-119&ip=203.0.113.250", nil)
	wrongIPV := httptest.NewRecorder()
	handler.ServeHTTP(wrongIPV, wrongIP)
	if wrongIPV.Code != http.StatusNoContent {
		t.Fatalf("hasJoined must reject mismatched optional ip: %d %s", wrongIPV.Code, wrongIPV.Body.String())
	}
	hr := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username="+username+"&serverId=server-hash-119", nil)
	hv := httptest.NewRecorder()
	handler.ServeHTTP(hv, hr)
	if hv.Code != http.StatusOK || !strings.Contains(hv.Body.String(), uuid) {
		t.Fatalf("hasJoined=%d %s", hv.Code, hv.Body.String())
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.Header.Set("Authorization", "Bearer "+neverToken)
	lo := httptest.NewRecorder()
	handler.ServeHTTP(lo, logout)
	if lo.Code != http.StatusOK {
		t.Fatalf("logout=%d %s", lo.Code, lo.Body.String())
	}
	vr = httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+mcToken+`"}`))
	vv = httptest.NewRecorder()
	handler.ServeHTTP(vv, vr)
	if vv.Code != http.StatusForbidden {
		t.Fatalf("minecraft token must die with parent Never session: %d %s", vv.Code, vv.Body.String())
	}
}

func TestMinecraftAuth119YggdrasilPasswordUsesFederationCore(t *testing.T) {
	handler := testServer(t)
	body := `{"username":"admin@neverlauncher.local","password":"admin","clientToken":"legacy-client","requestUser":true}`
	r := httptest.NewRequest(http.MethodPost, "/authserver/authenticate", strings.NewReader(body))
	v := httptest.NewRecorder()
	handler.ServeHTTP(v, r)
	if v.Code != http.StatusOK {
		t.Fatalf("authenticate=%d %s", v.Code, v.Body.String())
	}
	p := decodeMap119(t, v.Body)
	token, ok := p["accessToken"].(string)
	if !ok || !strings.HasPrefix(token, "nlmc_") {
		t.Fatalf("expected opaque minecraft token: %#v", p["accessToken"])
	}
	vr := httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+token+`","clientToken":"legacy-client"}`))
	vv := httptest.NewRecorder()
	handler.ServeHTTP(vv, vr)
	if vv.Code != http.StatusNoContent {
		t.Fatalf("validate=%d %s", vv.Code, vv.Body.String())
	}
}

func TestMinecraftAuth119RefreshConsumesOldToken(t *testing.T) {
	handler := testServer(t)
	auth := httptest.NewRequest(http.MethodPost, "/authserver/authenticate", strings.NewReader(`{"username":"admin@neverlauncher.local","password":"admin","clientToken":"refresh-client"}`))
	av := httptest.NewRecorder()
	handler.ServeHTTP(av, auth)
	if av.Code != http.StatusOK {
		t.Fatalf("authenticate=%d %s", av.Code, av.Body.String())
	}
	p := decodeMap119(t, av.Body)
	oldToken := p["accessToken"].(string)
	body := `{"accessToken":"` + oldToken + `","clientToken":"refresh-client"}`
	first := httptest.NewRequest(http.MethodPost, "/authserver/refresh", strings.NewReader(body))
	fv := httptest.NewRecorder()
	handler.ServeHTTP(fv, first)
	if fv.Code != http.StatusOK {
		t.Fatalf("first refresh=%d %s", fv.Code, fv.Body.String())
	}
	second := httptest.NewRequest(http.MethodPost, "/authserver/refresh", strings.NewReader(body))
	sv := httptest.NewRecorder()
	handler.ServeHTTP(sv, second)
	if sv.Code != http.StatusForbidden {
		t.Fatalf("replayed refresh token must be rejected: %d %s", sv.Code, sv.Body.String())
	}
}

func TestMinecraftAuth119PlayerRoleCanExchangeSession(t *testing.T) {
	cfg := config.Config{PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "test-secret-player-119", WebAuthnRPID: "example.test", WebAuthnRPName: "NeverLauncher Test", WebAuthnOrigins: []string{"http://example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	user, err := repo.SaveUser(model.User{Email: "player@example.test", DisplayName: "Player119", RoleID: "player", Status: "active", PasswordHash: hashPassword("player-password")})
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Version: "0.11.9-test", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}.Handler()
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"player@example.test","password":"player-password"}`))
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, login)
	if lr.Code != http.StatusOK {
		t.Fatalf("player login=%d %s user=%s", lr.Code, lr.Body.String(), user.ID)
	}
	p := decodeMap119(t, lr.Body)
	token := p["data"].(map[string]any)["tokens"].(map[string]any)["accessToken"].(string)
	ex := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{}`))
	ex.Header.Set("Authorization", "Bearer "+token)
	er := httptest.NewRecorder()
	h.ServeHTTP(er, ex)
	if er.Code != http.StatusCreated {
		t.Fatalf("player exchange=%d %s", er.Code, er.Body.String())
	}
}

func TestMinecraftAuth119ExchangeRejectsMalformedJSON(t *testing.T) {
	handler := testServer(t)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin"}`))
	login.Header.Set("Content-Type", "application/json")
	lr := httptest.NewRecorder()
	handler.ServeHTTP(lr, login)
	if lr.Code != http.StatusOK {
		t.Fatalf("login=%d %s", lr.Code, lr.Body.String())
	}
	p := decodeMap119(t, lr.Body)
	token := p["data"].(map[string]any)["tokens"].(map[string]any)["accessToken"].(string)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{"clientToken":`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	v := httptest.NewRecorder()
	handler.ServeHTTP(v, r)
	if v.Code != http.StatusBadRequest {
		t.Fatalf("malformed exchange body=%d %s", v.Code, v.Body.String())
	}
}

func TestMinecraftProfile119StableAcrossEmailChange(t *testing.T) {
	cfg := config.Config{PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "test-secret-profile-119", WebAuthnRPID: "example.test", WebAuthnRPName: "NeverLauncher Test", WebAuthnOrigins: []string{"http://example.test"}}
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
		t.Fatalf("profile must stay stable: before=%+v after=%+v", first, second)
	}
}

func TestYggdrasilMetadata119RootIsExact(t *testing.T) {
	h := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	v := httptest.NewRecorder()
	h.ServeHTTP(v, r)
	if v.Code != http.StatusOK || !strings.Contains(v.Body.String(), "NeverLauncher") {
		t.Fatalf("root metadata=%d %s", v.Code, v.Body.String())
	}
	metadata := decodeMap119(t, v.Body)
	meta, ok := metadata["meta"].(map[string]any)
	if !ok || meta["feature.non_email_login"] != true || meta["links"] == nil {
		t.Fatalf("invalid authlib-injector metadata: %#v", metadata)
	}
	if _, legacyTopLevel := metadata["feature"]; legacyTopLevel {
		t.Fatalf("feature flags must be inside meta: %#v", metadata)
	}
	r = httptest.NewRequest(http.MethodGet, "/removed-legacy-path", nil)
	v = httptest.NewRecorder()
	h.ServeHTTP(v, r)
	if v.Code != http.StatusNotFound {
		t.Fatalf("root handler must not swallow unknown paths: %d", v.Code)
	}
}

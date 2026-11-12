package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestBrowserReplayAcrossAPIReplicas0525(t *testing.T) {
	repo := repository.NewMemoryRepository("https://launcher.example.test")
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: strings.Repeat("a", 40)}
	setup := func() (*Server, http.Handler) {
		core := federation.New(repo)
		if err := core.RegisterWithPolicy(oidcFixtureConnector115{}, federation.ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
			t.Fatal(err)
		}
		srv := &Server{Version: "0.52.5", Config: cfg, Repo: repo, Federation: core, State: NewRuntimeState()}
		return srv, srv.Handler()
	}
	srvA, a := setup()
	_, b := setup()
	call := func(h http.Handler, uri string, doc any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, uri, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	begin := call(a, "/api/v1/auth/oidc/oidc-fixture/begin", map[string]any{"deviceId": "device-a"})
	if begin.Code != 200 {
		t.Fatalf("Начало операции: HTTP %d: %s", begin.Code, begin.Body.String())
	}
	var response struct {
		Data struct {
			State       string `json:"state"`
			Transaction string `json:"transaction"`
		} `json:"data"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	tx := response.Data.Transaction
	state := response.Data.State
	if tx == "" || state == "" {
		t.Fatal("Отсутствует защищённая транзакция")
	}
	endpoint := "/api/v1/auth/oidc/oidc-fixture/complete"
	payload := map[string]any{"code": "fixture-code", "state": state, "transaction": tx}
	// Непроверенная подмена устройства НЕ ДОЛЖНА расходовать запечатанную
	// транзакцию.
	wrongDevice := map[string]any{"code": "fixture-code", "state": state, "transaction": tx, "deviceId": "device-b"}
	if result := call(a, endpoint, wrongDevice); result.Code != 401 {
		t.Fatalf("Подмена устройства: HTTP %d", result.Code)
	}
	if result := call(a, endpoint, payload); result.Code != 200 {
		t.Fatalf("Корректный первый запрос: HTTP %d: %s", result.Code, result.Body.String())
	}
	if result := call(b, endpoint, payload); result.Code != 401 {
		t.Fatalf("Повтор через другую реплику: HTTP %d", result.Code)
	}
	opened, err := srvA.openOIDCTransaction115(tx)
	if err != nil {
		t.Fatal(err)
	}
	// Другой nonce AEAD или шифротекст при том же браузерном state не должен
	// обеспечивать обход.
	secondSeal, err := srvA.sealOIDCTransaction115(opened)
	if err != nil {
		t.Fatal(err)
	}
	if result := call(a, endpoint, map[string]any{"code": "fixture-code", "state": state, "transaction": secondSeal}); result.Code != 401 {
		t.Fatalf("Повтор с повторно защищёнными данными: HTTP %d", result.Code)
	}
	// Свежая браузерная транзакция остаётся пригодной после инцидента повтора.
	fresh := call(b, "/api/v1/auth/oidc/oidc-fixture/begin", map[string]any{"deviceId": "device-a"})
	if fresh.Code != 200 {
		t.Fatal("Не удалось начать новую операцию")
	}
	if err := json.Unmarshal(fresh.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if result := call(b, endpoint, map[string]any{"code": "fixture-code", "state": response.Data.State, "transaction": response.Data.Transaction}); result.Code != 200 {
		t.Fatalf("Новая транзакция: HTTP %d: %s", result.Code, result.Body.String())
	}
}

func TestBrowserLinkReplayAndLoginSeparation0525(t *testing.T) {
	repo := repository.NewMemoryRepository("https://launcher.example.test")
	cfg := config.Config{PublicURL: "https://launcher.example.test", Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: strings.Repeat("b", 40)}
	core := federation.New(repo)
	if err := core.RegisterWithPolicy(microsoftFixtureConnector116{}, federation.ProviderPolicy{AutoProvision: false}); err != nil {
		t.Fatal(err)
	}
	srv := Server{Version: "0.52.5", Config: cfg, Repo: repo, State: NewRuntimeState(), Federation: core}
	admin, err := repo.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := srv.issueLoginSession(admin, httptest.NewRequest(http.MethodGet, "/", nil), "device-a")
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	call := func(h http.Handler, path string, doc map[string]any, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(doc)
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request)
		return rec
	}
	begin := call(handler, "/api/v1/auth/microsoft/ms-fixture/link/begin", map[string]any{}, access)
	if begin.Code != 200 {
		t.Fatalf("Начало: %d %s", begin.Code, begin.Body.String())
	}
	var response struct {
		Data struct{ Transaction, State string } `json:"data"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	// Транзакцию привязки нельзя использовать для входа без токена владельца Launcher.
	login := call(handler, "/api/v1/auth/oidc/ms-fixture/complete", map[string]any{"code": "microsoft-code", "state": response.Data.State, "transaction": response.Data.Transaction}, "")
	if login.Code != 401 {
		t.Fatalf("Подмена привязки входом: HTTP %d", login.Code)
	}
	body := map[string]any{"code": "microsoft-code", "state": response.Data.State, "transaction": response.Data.Transaction}
	first := call(handler, "/api/v1/auth/microsoft/ms-fixture/link/complete", body, access)
	if first.Code != 200 {
		t.Fatalf("Привязка: HTTP %d: %s", first.Code, first.Body.String())
	}
	second := call(handler, "/api/v1/auth/microsoft/ms-fixture/link/complete", body, access)
	if second.Code != 401 {
		t.Fatalf("Повтор привязки: HTTP %d", second.Code)
	}
	// Неверный state не должен расходовать новую действительную транзакцию.
	begin = call(handler, "/api/v1/auth/microsoft/ms-fixture/link/begin", map[string]any{}, access)
	if begin.Code != 200 {
		t.Fatal("Ошибка новой транзакции привязки Microsoft")
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	wrong := call(handler, "/api/v1/auth/microsoft/ms-fixture/link/complete", map[string]any{"code": "microsoft-code", "state": "wrong", "transaction": response.Data.Transaction}, access)
	if wrong.Code != 401 {
		t.Fatalf("Несовпадение состояния: HTTP %d", wrong.Code)
	}
	legitimate := call(handler, "/api/v1/auth/microsoft/ms-fixture/link/complete", map[string]any{"code": "microsoft-code", "state": response.Data.State, "transaction": response.Data.Transaction}, access)
	if legitimate.Code != 200 {
		t.Fatalf("Новая допустимая привязка: HTTP %d: %s", legitimate.Code, legitimate.Body.String())
	}
}

func TestBrowserReplayAtomicMemory0525(t *testing.T) {
	repo := repository.NewMemoryRepository("https://launcher.example.test")
	srv := Server{Repo: repo}
	tx := oidcTransaction115{ProviderID: "oidc-fixture", State: "state-shared", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	requests := 20
	result := make(chan bool, requests)
	for i := 0; i < requests; i++ {
		go func() {
			rec := httptest.NewRecorder()
			result <- srv.claimBrowserTransaction0525(rec, httptest.NewRequest("POST", "/", nil), tx)
		}()
	}
	passed := 0
	for i := 0; i < requests; i++ {
		if <-result {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("Один и тот же nonce использован раз: %d", passed)
	}
}

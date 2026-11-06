package httpapi

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHWIDRiskNeverAutomaticallyRevokes0299(t *testing.T) {
	for _, tc := range []struct {
		reasons    []string
		wantAction string
	}{
		{[]string{"hwid-signal-changed"}, "step-up"},
		{[]string{"ip-changed", "hwid-signal-changed"}, "step-up"},
		{[]string{"ip-changed", "user-agent-changed", "hwid-signal-changed"}, "step-up"},
		{[]string{"hwid-signal-changed", "refresh-token-reuse"}, "revoke"},
	} {
		_, _, action := evaluateRiskReasons0126(tc.reasons)
		if action != tc.wantAction {
			t.Errorf("%v: получено %s, ожидалось %s", tc.reasons, action, tc.wantAction)
		}
	}
}
func TestHWIDDigestIsAccountScoped0299(t *testing.T) {
	hint := strings.Repeat("f", 64)
	a := hwidAccountDigest0299("secret", "alice", hint)
	b := hwidAccountDigest0299("secret", "bob", hint)
	if a == b || a == hint || len(a) != 64 {
		t.Fatal("Хеш HWID должен формироваться с ключом и быть привязан к учётной записи")
	}
	if a != hwidAccountDigest0299("secret", "alice", hint) {
		t.Fatal("Результат недетерминирован")
	}
}

// Удаление по требованию конфиденциальности по-прежнему разрешено, но не может
// сбросить уже повышенный уровень риска активного сеанса без необходимого
// усиленного подтверждения.
func TestHWIDRiskPersistsAfterPrivacyDeletion0433(t *testing.T) {
	cfg := config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "0123456789abcdef0123456789abcdef-hwid-sticky-risk", AuthTokenIssuer: "https://api.example.test", AuthTokenAudience: "launcher-api", WebAuthnRPID: "api.example.test", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://api.example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	h := Server{Version: "0.43.3", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(t.TempDir())}.Handler()
	bound := registerBoundSession0126(t, h)
	now := time.Now().UTC()
	first, second := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := repo.ObserveHWID0299(nil, bound.UserID, bound.DeviceID, first, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ObserveHWID0299(nil, bound.UserID, bound.DeviceID, second, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	code, out := deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/sessions", bound.Access, nil)
	if code != http.StatusOK {
		t.Fatalf("Проверка риска завершилась ошибкой: %d %#v", code, out)
	}
	before := deviceTrustData0121(t, out)
	items, ok := before["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("Отсутствует активный сеанс: %#v", before)
	}
	state, _ := items[0].(map[string]any)
	if state["riskAction"] != "step-up" {
		t.Fatalf("Изменение HWID не повысило оценку риска: %#v", state)
	}
	code, out = deviceTrustRequest0121(t, h, http.MethodDelete, "/api/v1/auth/hwid", bound.Access, nil)
	if code != http.StatusOK {
		t.Fatalf("Удаление персональных данных завершилось ошибкой: %d %#v", code, out)
	}
	code, out = deviceTrustRequest0121(t, h, http.MethodGet, "/api/v1/auth/sessions", bound.Access, nil)
	if code != http.StatusOK {
		t.Fatalf("Проверка сеанса завершилась ошибкой: %d %#v", code, out)
	}
	after := deviceTrustData0121(t, out)
	items, ok = after["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("После удаления персональных данных отсутствует сеанс: %#v", after)
	}
	state, _ = items[0].(map[string]any)
	if state["riskAction"] != "step-up" {
		t.Fatalf("Удаление персональных данных обошло политику сеансов: %#v", state)
	}
}

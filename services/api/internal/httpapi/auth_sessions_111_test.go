package httpapi

import (
	"errors"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestAuthSession111RefreshReplayRevokesFamily(t *testing.T) {
	store := newAuthSessionStore111()
	user := model.User{ID: "user-111", Email: "user@example.test", RoleID: "player"}
	req := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/auth/login", nil)
	req.Header.Set("User-Agent", "Launcher-Test/0.11.1")

	session, firstRefresh, err := store.create(user, req, "test-device")
	if err != nil {
		t.Fatalf("Создание сеанса: %v", err)
	}
	rotated, secondRefresh, err := store.rotate(firstRefresh)
	if err != nil {
		t.Fatalf("Первая ротация: %v", err)
	}
	if secondRefresh == firstRefresh {
		t.Fatal("Токен обновления должен меняться при ротации")
	}
	if rotated.RefreshFamily != session.RefreshFamily {
		t.Fatalf("Ротация изменила семейство токенов: %q != %q", rotated.RefreshFamily, session.RefreshFamily)
	}

	if _, _, err := store.rotate(firstRefresh); !errors.Is(err, errRefreshTokenReuseDetected) {
		t.Fatalf("Повторное использование должно компрометировать семейство токенов, получено: %v", err)
	}
	if store.active(session.ID, user.ID) {
		t.Fatal("Сеанс должен отзываться после повторного использования токена обновления")
	}
	if _, _, err := store.rotate(secondRefresh); !errors.Is(err, errRefreshTokenInvalid) {
		t.Fatalf("Действующий токен из скомпрометированного семейства должен отклоняться, получено: %v", err)
	}
}

func TestAuthSession111SummaryAdvertisesFamilyReuseDetection(t *testing.T) {
	store := newAuthSessionStore111()
	summary := store.summary()
	if got := summary["reuseDetection"]; got != "token-family" {
		t.Fatalf("Неожиданный результат reuseDetection: %#v", got)
	}
}

package httpapi

import (
	"errors"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestAuthSession111RefreshReplayRevokesFamily(t *testing.T) {
	store := newAuthSessionStore111()
	user := model.User{ID: "user-111", Email: "user@example.test", RoleID: "player"}
	req := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/auth/login", nil)
	req.Header.Set("User-Agent", "NeverLauncher-Test/0.11.1")

	session, firstRefresh, err := store.create(user, req, "test-device")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	rotated, secondRefresh, err := store.rotate(firstRefresh)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if secondRefresh == firstRefresh {
		t.Fatal("refresh token must rotate")
	}
	if rotated.RefreshFamily != session.RefreshFamily {
		t.Fatalf("rotation changed family: %q != %q", rotated.RefreshFamily, session.RefreshFamily)
	}

	if _, _, err := store.rotate(firstRefresh); !errors.Is(err, errRefreshTokenReuseDetected) {
		t.Fatalf("replay must compromise family, got: %v", err)
	}
	if store.active(session.ID, user.ID) {
		t.Fatal("session must be revoked after refresh-token replay")
	}
	if _, _, err := store.rotate(secondRefresh); !errors.Is(err, errRefreshTokenInvalid) {
		t.Fatalf("current token from compromised family must be rejected, got: %v", err)
	}
}

func TestAuthSession111SummaryAdvertisesFamilyReuseDetection(t *testing.T) {
	store := newAuthSessionStore111()
	summary := store.summary()
	if got := summary["reuseDetection"]; got != "token-family" {
		t.Fatalf("unexpected reuseDetection: %#v", got)
	}
}

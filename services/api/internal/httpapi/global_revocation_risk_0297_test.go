package httpapi

import (
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestCompromisedRiskRevokesSessionAndRefreshMemory0297(t *testing.T) {
	store := newAuthSessionStore111()
	user := model.User{ID: "user-0297", Email: "risk-0297@example.test", RoleID: "player", Status: "active"}
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	session, refresh, err := store.create(user, req, "desktop-0297")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.get(session.ID, user.ID); !ok {
		t.Fatal("session never active")
	}
	now := time.Now().UTC()
	rec, err := store.applyRisk0126(session.ID, user.ID, "compromised", 100, "revoke", []string{"device-revoked"}, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "revoked" || rec.RevokedReason != "risk-compromised" {
		t.Fatalf("risk decision left session active: %+v", rec)
	}
	if _, ok := store.get(session.ID, user.ID); ok {
		t.Fatal("revoked session remained valid")
	}
	if _, err := store.previewRefresh0126(refresh); err == nil {
		t.Fatal("risk-revoked refresh token remained valid")
	}
}

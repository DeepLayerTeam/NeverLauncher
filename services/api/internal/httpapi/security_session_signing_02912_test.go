package httpapi

import (
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestSessionSigningFailureRevokesRefreshFamily02912(t *testing.T) {
	repo := repository.NewMemoryRepository("https://api.example.test")
	admin, err := repo.GetUserByEmail("admin@launcher.local")
	if err != nil {
		t.Fatal(err)
	}
	state := NewRuntimeState()
	srv := Server{Repo: repo, State: state, Config: config.Config{RepositoryDriver: "memory", AuthTokenSecret: ""}}
	r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	if access, refresh, _, err := srv.issueLoginSessionWithAuth(admin, r, "e2e-device", []string{"password"}, "single-factor", time.Now().UTC(), "", "local"); err == nil || access != "" || refresh != "" {
		t.Fatalf("invalid token signing key minted session: access=%v refresh=%v err=%v", access != "", refresh != "", err)
	}
	sessions := state.AuthSessions.listByUser(admin.ID)
	if len(sessions) != 1 || sessions[0].Status != "revoked" {
		t.Fatalf("failed signing left a usable session: %+v", sessions)
	}
}

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/protection"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProtectionBlocksAuthLaunchJoinAndRestoresAfterUnban0298(t *testing.T) {
	repo := repository.NewMemoryRepository("")
	if _, err := repo.SaveUser(model.User{ID: "user-0298", Email: "test-user-0298@example.test", Status: "active", RoleID: "player"}); err != nil {
		t.Fatal(err)
	}
	server := Server{Repo: repo}
	ctx := context.Background()
	userID := "user-0298"
	for _, stage := range []protection.Stage{protection.BeforeAuth, protection.AfterAuth, protection.BeforeLaunch, protection.BeforeJoin} {
		if decision := server.evaluateProtection0298(ctx, protection.Request{Stage: stage, UserID: userID}); !decision.Allowed() {
			t.Fatalf("unexpected policy denial %+v", decision)
		}
	}
	if err := repo.SetProtectionBan(ctx, repository.ProtectionBan{UserID: userID, Reason: "security ban", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []protection.Stage{protection.BeforeAuth, protection.AfterAuth, protection.BeforeLaunch, protection.BeforeJoin} {
		if decision := server.evaluateProtection0298(ctx, protection.Request{Stage: stage, UserID: userID}); decision.Action != protection.Deny || decision.Reason != "account_banned" {
			t.Fatalf("ban bypassed %s: %+v", stage, decision)
		}
	}
	if _, err := repo.RevokeProtectionBan(ctx, userID, "admin"); err != nil {
		t.Fatal(err)
	}
	if decision := server.evaluateProtection0298(ctx, protection.Request{Stage: protection.BeforeAuth, UserID: userID}); !decision.Allowed() {
		t.Fatalf("unban did not restore eligibility %+v", decision)
	}
}

func TestBannedUserCannotReceiveNeverSession0298(t *testing.T) {
	repo := repository.NewMemoryRepository("")
	if _, err := repo.SaveUser(model.User{ID: "banned-user", Email: "banned@example.test", RoleID: "player", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetProtectionBan(context.Background(), repository.ProtectionBan{UserID: "banned-user", Reason: "policy violation", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	server := Server{Repo: repo, State: NewRuntimeState()}
	request := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	_, _, _, err := server.issueLoginSessionWithAuth(model.User{ID: "banned-user", Email: "banned@example.test", RoleID: "player", Status: "active"}, request, "desktop", []string{"password"}, "single-factor", time.Now().UTC(), "", "local")
	if !errors.Is(err, errAuthRequired) {
		t.Fatalf("banned user received new session: %v", err)
	}
}

func TestProtectionBanUnbanLiveHTTP0298(t *testing.T) {
	handler := testServer(t)
	admin := loginAdmin(t, handler)
	admin, _ = registerTestPasskey117(t, handler, admin)
	created := request0211(t, handler, http.MethodPost, "/api/v1/admin/users", admin, `{"email":"ban0298@example.test","displayName":"Ban Test","roleId":"player","password":"safe-password-0298"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("user create: %d %s", created.Code, created.Body.String())
	}
	var account struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &account); err != nil || account.ID == "" {
		t.Fatalf("account: %v %s", err, created.Body.String())
	}
	player := loginUser0211(t, handler, "ban0298@example.test", "safe-password-0298")
	banned := request0211(t, handler, http.MethodPost, "/api/v1/admin/protection/users/"+account.ID+"/ban", admin, `{"reason":"confirmed session abuse"}`)
	if banned.Code != http.StatusOK {
		t.Fatalf("ban: %d %s", banned.Code, banned.Body.String())
	}
	if res := request0211(t, handler, http.MethodGet, "/api/v1/auth/sessions", player, ""); res.Code != http.StatusUnauthorized {
		t.Fatalf("ban did not revoke live token: %d %s", res.Code, res.Body.String())
	}
	refused := request0211(t, handler, http.MethodPost, "/api/v1/admin/login", "", `{"email":"ban0298@example.test","password":"safe-password-0298"}`)
	if refused.Code != http.StatusForbidden {
		t.Fatalf("ban did not block new login: %d %s", refused.Code, refused.Body.String())
	}
	lifted := request0211(t, handler, http.MethodPost, "/api/v1/admin/protection/users/"+account.ID+"/unban", admin, `{}`)
	if lifted.Code != http.StatusOK {
		t.Fatalf("unban: %d %s", lifted.Code, lifted.Body.String())
	}
	recovered := request0211(t, handler, http.MethodPost, "/api/v1/admin/login", "", `{"email":"ban0298@example.test","password":"safe-password-0298"}`)
	if recovered.Code != http.StatusOK {
		t.Fatalf("unbanned user still denied: %d %s", recovered.Code, recovered.Body.String())
	}
	if res := request0211(t, handler, http.MethodGet, "/api/v1/auth/sessions", player, ""); res.Code != http.StatusUnauthorized {
		t.Fatalf("unban resurrected revoked token: %d %s", res.Code, res.Body.String())
	}
}

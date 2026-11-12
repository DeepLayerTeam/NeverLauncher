package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRoleUpdateRevokesLiveLauncherToken0297(t *testing.T) {
	handler := testServer(t)
	owner := loginAdmin(t, handler)
	created := request0211(t, handler, http.MethodPost, "/api/v1/admin/users", owner,
		`{"email":"revocation-0297@example.test","displayName":"Revocation","roleId":"player","password":"a-real-password-0297"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("создание: %d %s", created.Code, created.Body.String())
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil || user.ID == "" {
		t.Fatalf("Создание идентификатора: %s / %v", created.Body.String(), err)
	}
	token := loginUser0211(t, handler, "revocation-0297@example.test", "a-real-password-0297")
	current := request0211(t, handler, http.MethodGet, "/api/v1/auth/sessions", token, "")
	if current.Code != http.StatusOK {
		t.Fatalf("Активный сеанс: %d %s", current.Code, current.Body.String())
	}
	changed := request0211(t, handler, http.MethodPatch, "/api/v1/admin/users/"+user.ID, owner, `{"roleId":"viewer"}`)
	if changed.Code != http.StatusOK {
		t.Fatalf("Обновление роли: %d %s", changed.Code, changed.Body.String())
	}
	revoked := request0211(t, handler, http.MethodGet, "/api/v1/auth/sessions", token, "")
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("Устаревшая роль сохранила доступ: %d %s", revoked.Code, revoked.Body.String())
	}
}

package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRoleUpdateRevokesLiveNeverToken0297(t *testing.T) {
	handler := testServer(t)
	owner := loginAdmin(t, handler)
	created := request0211(t, handler, http.MethodPost, "/api/v1/admin/users", owner,
		`{"email":"revocation-0297@example.test","displayName":"Revocation","roleId":"player","password":"a-real-password-0297"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil || user.ID == "" {
		t.Fatalf("created identity: %s / %v", created.Body.String(), err)
	}
	token := loginUser0211(t, handler, "revocation-0297@example.test", "a-real-password-0297")
	current := request0211(t, handler, http.MethodGet, "/api/v1/auth/sessions", token, "")
	if current.Code != http.StatusOK {
		t.Fatalf("active session: %d %s", current.Code, current.Body.String())
	}
	changed := request0211(t, handler, http.MethodPatch, "/api/v1/admin/users/"+user.ID, owner, `{"roleId":"viewer"}`)
	if changed.Code != http.StatusOK {
		t.Fatalf("role update: %d %s", changed.Code, changed.Body.String())
	}
	revoked := request0211(t, handler, http.MethodGet, "/api/v1/auth/sessions", token, "")
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("stale role retained access: %d %s", revoked.Code, revoked.Body.String())
	}
}

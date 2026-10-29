package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Exercises the real HTTP mux, the live authorization service and session
// revocation instead of assuming that hiding a button is sufficient.
func TestProjectMembership0387IsScopedAuditedAndRevocable(t *testing.T) {
	h := testServer(t)
	owner := loginAdmin(t, h)
	other := request0211(t, h, http.MethodPost, "/api/v1/admin/projects", owner, `{"id":"other-0387","name":"Other"}`)
	if other.Code != http.StatusCreated {
		t.Fatalf("project: %d %s", other.Code, other.Body.String())
	}
	made := request0211(t, h, http.MethodPost, "/api/v1/admin/users", owner, `{"email":"operator-0387@example.test","displayName":"Operator","roleId":"player","password":"operator-pass-0387"}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("user: %d %s", made.Code, made.Body.String())
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &user); err != nil || user.ID == "" {
		t.Fatalf("user: %s %v", made.Body.String(), err)
	}
	actor := loginUser0211(t, h, "operator-0387@example.test", "operator-pass-0387")
	path := "/api/v1/admin/users/" + user.ID
	denied := request0211(t, h, http.MethodPatch, path, actor, `{"projectRoles":{"demo-project":"owner"}}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("operator escalated: %d %s", denied.Code, denied.Body.String())
	}
	weak := request0211(t, h, http.MethodPatch, path, owner, `{"projectRoles":{"demo-project":"operator"},"expectedProjectRoles":{}}`)
	if weak.Code == http.StatusOK {
		t.Fatalf("role changed without recent passkey MFA: %s", weak.Body.String())
	}
	privilegedCreate := request0211(t, h, http.MethodPost, "/api/v1/admin/users", owner, `{"email":"unverified-0387@example.test","roleId":"player","password":"a-strong-password-0387","projectRoles":{"demo-project":"operator"}}`)
	if privilegedCreate.Code == http.StatusCreated {
		t.Fatal("privileged creation bypassed passkey MFA")
	}
	globalAdminCreate := request0211(t, h, http.MethodPost, "/api/v1/admin/users", owner, `{"email":"unverified-admin-0387@example.test","roleId":"admin","password":"a-strong-password-0387"}`)
	if globalAdminCreate.Code == http.StatusCreated {
		t.Fatal("global admin creation bypassed passkey MFA")
	}
	owner, _ = registerTestPasskey117(t, h, owner)
	grant := request0211(t, h, http.MethodPatch, path, owner, `{"projectRoles":{"demo-project":"operator"},"expectedProjectRoles":{}}`)
	if grant.Code != http.StatusOK {
		t.Fatalf("grant: %d %s", grant.Code, grant.Body.String())
	}
	stale := request0211(t, h, http.MethodPatch, path, owner, `{"projectRoles":{"demo-project":"viewer"},"expectedProjectRoles":{}}`)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale membership should conflict: %d %s", stale.Code, stale.Body.String())
	}
	unknown := request0211(t, h, http.MethodPatch, path, owner, `{"projectRoles":{"does-not-exist":"operator"}}`)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown project: %d %s", unknown.Code, unknown.Body.String())
	}
	wildcard := request0211(t, h, http.MethodPatch, path, owner, `{"projectRoles":{"*":"owner"}}`)
	if wildcard.Code != http.StatusBadRequest {
		t.Fatalf("wildcard project: %d %s", wildcard.Code, wildcard.Body.String())
	}
	// The original token is revoked on membership changes, requiring a fresh login.
	blocked := request0211(t, h, http.MethodPatch, "/api/v1/admin/projects/demo-project", actor, `{"description":"should-not-change"}`)
	if blocked.Code == http.StatusOK {
		t.Fatal("old token unexpectedly changed project")
	}
	actor = loginUser0211(t, h, "operator-0387@example.test", "operator-pass-0387")
	allowed := request0211(t, h, http.MethodPatch, "/api/v1/admin/projects/demo-project", actor, `{"description":"operator-updated-0387"}`)
	if allowed.Code != http.StatusOK {
		t.Fatalf("own project: %d %s", allowed.Code, allowed.Body.String())
	}
	for _, endpoint := range []string{"/api/v1/admin/users", "/api/v1/operations/backend/status", "/api/v1/admin/config"} {
		forbiddenGlobal := request0211(t, h, http.MethodGet, endpoint, actor, "")
		if forbiddenGlobal.Code != http.StatusForbidden {
			t.Fatalf("project operator reached global endpoint %s: %d %s", endpoint, forbiddenGlobal.Code, forbiddenGlobal.Body.String())
		}
	}
	forbidden := request0211(t, h, http.MethodPatch, "/api/v1/admin/projects/other-0387", actor, `{"description":"forbidden"}`)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("other project: %d %s", forbidden.Code, forbidden.Body.String())
	}
	revoke := request0211(t, h, http.MethodPatch, path, owner, `{"projectRoles":{},"expectedProjectRoles":{"demo-project":"operator"}}`)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoke.Code, revoke.Body.String())
	}
	blocked = request0211(t, h, http.MethodPatch, "/api/v1/admin/projects/demo-project", actor, `{"description":"after-revoke"}`)
	if blocked.Code == http.StatusOK {
		t.Fatal("revoked operator could still mutate")
	}
	audit := request0211(t, h, http.MethodGet, "/api/v1/admin/audit", owner, "")
	if audit.Code != http.StatusOK || !strings.Contains(audit.Body.String(), "user:project-role:granted") || !strings.Contains(audit.Body.String(), "user:project-role:revoked") {
		t.Fatalf("missing membership audit: %d %s", audit.Code, audit.Body.String())
	}
}

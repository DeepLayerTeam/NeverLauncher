package httpapi

import (
	"net/http"
	"testing"
)

func TestTextureAdminRBAC0259(t *testing.T) {
	h := testServer(t)
	admin := loginAdmin(t, h)
	rr := request0211(t, h, "POST", "/api/v1/admin/users", admin, `{"email":"textures-viewer@example.test","displayName":"Viewer","roleId":"player","password":"test-password-0259"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("setup user: %d %s", rr.Code, rr.Body.String())
	}
	viewer := loginUser0211(t, h, "textures-viewer@example.test", "test-password-0259")
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/admin/textures/policy", ""},
		{"GET", "/api/v1/admin/textures/policy/history", ""},
		{"GET", "/api/v1/admin/textures/exceptions", ""},
		{"GET", "/api/v1/admin/textures/default-options", ""},
		{"PUT", "/api/v1/admin/textures/policy", `{"expectedRevision":0}`},
		{"PUT", "/api/v1/admin/textures/exceptions/alice", `{"kind":"cape","decision":"allow"}`},
	} {
		anon := request0211(t, h, tc.method, tc.path, "", tc.body)
		if anon.Code != 401 {
			t.Errorf("anonymous %s %s: %d", tc.method, tc.path, anon.Code)
		}
		denied := request0211(t, h, tc.method, tc.path, viewer, tc.body)
		if denied.Code != 403 {
			t.Errorf("viewer %s %s: %d", tc.method, tc.path, denied.Code)
		}
	}
}

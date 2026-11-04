package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerBridgeRegistration0383RejectsForeignOrUnknownProfile(t *testing.T) {
	h := testServer(t)
	token := loginAdmin(t, h)
	for _, tc := range []struct{ project, profile string }{
		{"demo-project", "profile-does-not-exist-0383"},
		{"nonexistent-project-0383", "vanilla"},
	} {
		key := newTestBridgeNodeIdentity0142(t)
		res := registerTestBridgeNode0142(t, h, token, "binding-0383-"+tc.project, "Wrong binding", "paper", tc.project, tc.profile, key)
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "профил") && !strings.Contains(res.Body.String(), "проект") {
			t.Fatalf("unexpected registration acceptance for %s/%s: %d %s", tc.project, tc.profile, res.Code, res.Body.String())
		}
	}
	// The server must not have been registered as a side effect of rejection.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server-bridge/projects/demo-project/overview", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), `"id":"binding-0383-demo-project"`) {
		t.Fatalf("failed registration persisted unexpectedly: %d %s", res.Code, res.Body.String())
	}
}

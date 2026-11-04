package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationalConfigAdminRoutes02111(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	send := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	get := send("GET", "/api/v1/admin/config", "")
	if get.Code != 200 || !strings.Contains(get.Body.String(), `"auditDefaultPageSize":25`) {
		t.Fatalf("GET: %d %s", get.Code, get.Body.String())
	}
	bad := send("POST", "/api/v1/admin/config/validate", `{"expectedRevision":1,"reason":"check settings","settings":{"auditDefaultPageSize":500}}`)
	if bad.Code != 400 || !strings.Contains(bad.Body.String(), "invalid_field") {
		t.Fatalf("invalid config: %d %s", bad.Code, bad.Body.String())
	}
	ok := send("POST", "/api/v1/admin/config/validate", `{"expectedRevision":1,"reason":"check settings","settings":{"auditDefaultPageSize":30,"auditMaxPageSize":100,"auditLookbackDays":30,"jobsDefaultPageSize":25,"jobsMaxPageSize":100}}`)
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), `"restartRequired":false`) {
		t.Fatalf("validate: %d %s", ok.Code, ok.Body.String())
	}
	clash := send("POST", "/api/v1/admin/config/validate", `{"expectedRevision":77,"reason":"check settings","settings":{"auditDefaultPageSize":30,"auditMaxPageSize":100,"auditLookbackDays":30,"jobsDefaultPageSize":25,"jobsMaxPageSize":100}}`)
	if clash.Code != 409 || !strings.Contains(clash.Body.String(), "revision_conflict") {
		t.Fatalf("conflict: %d %s", clash.Code, clash.Body.String())
	}
	denied := send("GET", "/api/v1/admin/audit?limit=9999", "")
	if denied.Code != 400 || !strings.Contains(denied.Body.String(), "invalid_limit") {
		t.Fatalf("audit bounds: %d %s", denied.Code, denied.Body.String())
	}
	okAudit := send("GET", "/api/v1/admin/audit?limit=10&action=config", "")
	if okAudit.Code != 200 || !strings.Contains(okAudit.Body.String(), `"items"`) {
		t.Fatalf("audit: %d %s", okAudit.Code, okAudit.Body.String())
	}
}

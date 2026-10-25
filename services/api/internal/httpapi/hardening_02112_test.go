package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// These requests go through the real mux, auth middleware and RBAC decision.
func TestHardening02112NegativeRBAC(t *testing.T) {
	h := testServer(t)
	admin := loginAdmin(t, h)
	made := request0211(t, h, http.MethodPost, "/api/v1/admin/projects", admin, `{"id":"hardening-other","name":"Other","defaultChannel":"stable"}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("project: %d %s", made.Code, made.Body.String())
	}
	made = request0211(t, h, http.MethodPost, "/api/v1/admin/users", admin, `{"email":"hardening-operator@example.test","displayName":"Operator","roleId":"player","password":"hardening-password","projectRoles":{"demo-project":"operator"}}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("user: %d %s", made.Code, made.Body.String())
	}
	token := loginUser0211(t, h, "hardening-operator@example.test", "hardening-password")
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/api/v1/operations/jobs?projectId=hardening-other", "", http.StatusForbidden},
		{"GET", "/api/v1/server-bridge/projects/hardening-other/overview", "", http.StatusForbidden},
		{"GET", "/api/v1/admin/config", "", http.StatusForbidden},
		{"GET", "/api/v1/operations/backend/status", "", http.StatusForbidden},
		{"GET", "/api/v1/operations/backend/clients", "", http.StatusForbidden},
		{"POST", "/api/v1/operations/backend/config/reload", "", http.StatusForbidden},
		{"POST", "/api/v1/operations/backend/notify", `{ "userId": "admin", "message": "Hello" }`, http.StatusForbidden},
		{"POST", "/api/v1/operations/backend/restart", `{ "instanceId": "invalid" }`, http.StatusForbidden},
		{"GET", "/api/v1/admin/config/revisions", "", http.StatusForbidden},
		{"GET", "/api/v1/admin/audit?limit=10", "", http.StatusForbidden},
		{"POST", "/api/v1/admin/config/validate", `{"expectedRevision":1}`, http.StatusForbidden},
		{"POST", "/api/v1/release-drafts", `{"projectId":"hardening-other","profileId":"vanilla","channel":"stable","version":"0.21.12"}`, http.StatusForbidden},
		{"GET", "/api/v1/release-drafts?projectId=hardening-other", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		rr := request0211(t, h, tc.method, tc.path, token, tc.body)
		if rr.Code != tc.want {
			t.Errorf("%s %s: status %d want %d: %s", tc.method, tc.path, rr.Code, tc.want, rr.Body.String())
		}
	}
	// ServerBridge and settings require authentication before any data leaks.
	for _, path := range []string{"/api/v1/server-bridge/projects/demo-project/overview", "/api/v1/admin/config", "/api/v1/operations/jobs?projectId=demo-project"} {
		rr := request0211(t, h, "GET", path, "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestHardening02112AttemptJournalOmitsInternalLeaseData(t *testing.T) {
	entries := []model.DurableJobAttempt{{ID: 9, JobID: "internal-job", Attempt: 1, WorkerID: "secret-worker", LeaseFence: 777, Status: "failed", Error: "network failure", StartedAt: time.Now().UTC()}}
	b, err := json.Marshal(map[string]any{"attempts": publicOperationAttempts02112(entries)})
	if err != nil {
		t.Fatal(err)
	}
	for _, internal := range []string{"secret-worker", "workerId", "leaseFence", "internal-job", "777"} {
		if strings.Contains(string(b), internal) {
			t.Fatalf("internal durable metadata disclosed: %s", b)
		}
	}
	if !strings.Contains(string(b), `"attempt":1`) || !strings.Contains(string(b), `"status":"failed"`) {
		t.Fatalf("missing public attempt details: %s", b)
	}
}

// Concurrent tabs submit the same revision. Exactly one mutation can win.
func TestHardening02112TwoTabConfigCAS(t *testing.T) {
	h := testServer(t)
	token := loginAdmin(t, h)
	token, _ = registerTestPasskey117(t, h, token)
	body := `{"expectedRevision":1,"reason":"concurrent tabs test","settings":{"auditDefaultPageSize":30,"auditMaxPageSize":100,"auditLookbackDays":30,"auditExposeClientDetails":false,"jobsDefaultPageSize":25,"jobsMaxPageSize":100}}`
	first := request0211(t, h, "PUT", "/api/v1/admin/config", token, body)
	if first.Code != http.StatusOK {
		t.Fatalf("tab one: %d %s", first.Code, first.Body.String())
	}
	second := request0211(t, h, "PUT", "/api/v1/admin/config", token, body)
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "revision_conflict") {
		t.Fatalf("tab two accepted stale revision: %d %s", second.Code, second.Body.String())
	}
	current := request0211(t, h, "GET", "/api/v1/admin/config", token, "")
	if current.Code != http.StatusOK || !strings.Contains(current.Body.String(), `"revision":2`) {
		t.Fatalf("unexpected config after conflict: %d %s", current.Code, current.Body.String())
	}
}

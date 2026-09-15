package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalAdminCRUDProductFlow(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	auth := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
	}

	steps := []struct {
		method string
		path   string
		body   string
		code   int
		want   string
	}{
		{http.MethodPost, "/api/v1/admin/projects", `{"id":"crud-project","name":"CRUD Project","defaultChannel":"stable"}`, http.StatusCreated, "crud-project"},
		{http.MethodPatch, "/api/v1/admin/projects/crud-project", `{"description":"updated project"}`, http.StatusOK, "updated"},
		{http.MethodPost, "/api/v1/admin/projects/crud-project/profiles", `{"id":"vanilla","name":"Vanilla","loader":"vanilla"}`, http.StatusCreated, "vanilla"},
		{http.MethodPatch, "/api/v1/admin/projects/crud-project/profiles/vanilla", `{"description":"updated profile","loader":"fabric"}`, http.StatusOK, "fabric"},
		{http.MethodPost, "/api/v1/admin/projects/crud-project/channels", `{"id":"stable","name":"stable","protected":true}`, http.StatusCreated, "stable"},
		{http.MethodPatch, "/api/v1/admin/projects/crud-project/channels/stable", `{"description":"updated channel","protected":true}`, http.StatusOK, "updated channel"},
	}

	for _, step := range steps {
		req := httptest.NewRequest(step.method, step.path, strings.NewReader(step.body))
		auth(req)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != step.code || !strings.Contains(res.Body.String(), step.want) {
			t.Fatalf("%s %s => %d %s; want %d and %q", step.method, step.path, res.Code, res.Body.String(), step.code, step.want)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", strings.NewReader(`{"email":"operator@example.test","displayName":"Operator","roleId":"viewer","password":"ChangeMe-8.2.0"}`))
	auth(req)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), "operator@example.test") {
		t.Fatalf("create user => %d %s", res.Code, res.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("user id not found: %v body=%s", err, res.Body.String())
	}

	for _, path := range []string{"/api/v1/admin/users/" + created.ID + "/disable", "/api/v1/admin/users/" + created.ID + "/enable"} {
		req = httptest.NewRequest(http.MethodPost, path, nil)
		auth(req)
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s => %d %s", path, res.Code, res.Body.String())
		}
	}
}

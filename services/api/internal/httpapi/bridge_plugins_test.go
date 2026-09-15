package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalBridgePluginFlow(t *testing.T) {
	handler := testServer(t)
	adminToken := loginAdmin(t, handler)

	for _, path := range []string{
		"/api/v1/server-bridge/plugin-manifest",
		"/api/v1/server-bridge/plugin-compatibility",
		"/api/v1/server-bridge/diagnostics",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("GET %s => %d %s", path, res.Code, res.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/register", strings.NewReader(`{"id":"velocity-940","name":"Velocity 940","kind":"velocity","projectId":"demo-project","profileId":"vanilla"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("register => %d %s", res.Code, res.Body.String())
	}
	var registered struct {
		Data struct {
			ServerToken string `json:"serverToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &registered); err != nil || registered.Data.ServerToken == "" {
		t.Fatalf("server token missing: %v %s", err, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/velocity-940/heartbeat", strings.NewReader(`{"serverType":"velocity","pluginVersion":"0.10.1"}`))
	req.Header.Set("X-NeverLauncher-Server-Token", registered.Data.ServerToken)
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "heartbeat-accepted") {
		t.Fatalf("heartbeat => %d %s", res.Code, res.Body.String())
	}
}

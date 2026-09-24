package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalServerBridgeAuthFlow(t *testing.T) {
	handler := testServer(t)
	adminToken := loginAdmin(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/register", strings.NewReader(`{"id":"velocity-main","name":"Velocity Main","kind":"velocity","projectId":"demo-project","profileId":"vanilla","fingerprint":"ssh-ed25519:test"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("register server => %d %s", res.Code, res.Body.String())
	}
	var registered struct {
		Data struct {
			ServerToken string `json:"serverToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &registered); err != nil || registered.Data.ServerToken == "" {
		t.Fatalf("server token отсутствует: err=%v body=%s", err, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@neverlauncher.local","password":"admin","deviceId":"desktop-smoke"}`))
	req.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(req)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("player login => %d %s", res.Code, res.Body.String())
	}
	var loginPayload struct {
		Data struct {
			Tokens struct {
				AccessToken string `json:"accessToken"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &loginPayload); err != nil || loginPayload.Data.Tokens.AccessToken == "" {
		t.Fatalf("access token отсутствует: err=%v body=%s", err, res.Body.String())
	}
	loginPayload.Data.Tokens.AccessToken = bindAccessToken0127(t, handler, loginPayload.Data.Tokens.AccessToken, "ServerBridge test device").Access

	req = httptest.NewRequest(http.MethodPost, "/api/v1/session/join", strings.NewReader(`{"serverId":"velocity-main","projectId":"demo-project","profileId":"vanilla","channel":"stable","username":"AdminPlayer"}`))
	req.Header.Set("Authorization", "Bearer "+loginPayload.Data.Tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(req)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "joined") {
		t.Fatalf("session join => %d %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/session/has-joined?username=AdminPlayer&serverId=velocity-main", nil)
	req.Header.Set("X-NeverLauncher-Server-Token", registered.Data.ServerToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "neverlauncher") {
		t.Fatalf("has-joined => %d %s", res.Code, res.Body.String())
	}
	var joined struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &joined); err != nil || joined.ID == "" {
		t.Fatalf("uuid отсутствует: err=%v body=%s", err, res.Body.String())
	}

	// Protocol v2 join tickets are one-time. A replay of the same server-side
	// validation must not authorize the player again after the successful consume.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/session/has-joined?username=AdminPlayer&serverId=velocity-main", nil)
	req.Header.Set("X-NeverLauncher-Server-Token", registered.Data.ServerToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("replayed has-joined must be denied => %d %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/textures/"+joined.ID, nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "textures") {
		t.Fatalf("textures => %d %s", res.Code, res.Body.String())
	}

}

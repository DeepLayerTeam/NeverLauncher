package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setDeviceTrustClientMeta0127(req *http.Request) {
	req.Header.Set("User-Agent", "NeverLauncher-DeviceTrust-Test/0.12.1")
	req.RemoteAddr = "203.0.113.10:4242"
}

type boundAccess0127 struct {
	Access       string
	DeviceID     string
	BindingEpoch int64
	Private      ed25519.PrivateKey
}

func bindAccessToken0127(t *testing.T, h http.Handler, access, name string) boundAccess0127 {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code, out := deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/begin", access, map[string]any{
		"name": name, "platform": "linux", "clientVersion": "0.12.7",
	})
	if code != http.StatusOK {
		t.Fatalf("device register begin=%d %#v", code, out)
	}
	begin := deviceTrustData0121(t, out)
	payload, _ := begin["signingPayload"].(string)
	code, out = deviceTrustRequest0121(t, h, http.MethodPost, "/api/v1/auth/devices/register/complete", access, map[string]any{
		"challengeId": begin["challengeId"],
		"deviceId":    begin["deviceId"],
		"challenge":   begin["challenge"],
		"publicKey":   base64.RawURLEncoding.EncodeToString(pub),
		"signature":   base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload))),
	})
	if code != http.StatusCreated {
		t.Fatalf("device register complete=%d %#v", code, out)
	}
	data := deviceTrustData0121(t, out)
	session, _ := data["session"].(map[string]any)
	epoch, _ := session["bindingEpoch"].(float64)
	device, _ := data["device"].(map[string]any)
	bound := boundAccess0127{
		Access:       data["accessToken"].(string),
		DeviceID:     device["id"].(string),
		BindingEpoch: int64(epoch),
		Private:      priv,
	}
	if bound.Access == "" || bound.DeviceID == "" || bound.BindingEpoch < 2 {
		t.Fatalf("incomplete bound session: %#v", data)
	}
	return bound
}

func TestMinecraftTrust0127RequiresBoundDeviceAndInvalidatesTokenAfterRebind(t *testing.T) {
	h := testServer(t)
	access, _ := deviceTrustLogin0121(t, h, "mc-trust-0127")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{"clientToken":"trust-client"}`))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(req)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPreconditionRequired || !strings.Contains(rr.Body.String(), "trusted_device_required") {
		t.Fatalf("unbound minecraft exchange was not denied: %d %s", rr.Code, rr.Body.String())
	}

	bound := bindAccessToken0127(t, h, access, "Minecraft trust device A")
	req = httptest.NewRequest(http.MethodPost, "/api/v1/minecraft/session", strings.NewReader(`{"clientToken":"trust-client"}`))
	req.Header.Set("Authorization", "Bearer "+bound.Access)
	req.Header.Set("Content-Type", "application/json")
	setDeviceTrustClientMeta0127(req)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("bound minecraft exchange=%d %s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	mcToken := created["data"].(map[string]any)["accessToken"].(string)

	validate := httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+mcToken+`","clientToken":"trust-client"}`))
	vv := httptest.NewRecorder()
	h.ServeHTTP(vv, validate)
	if vv.Code != http.StatusNoContent {
		t.Fatalf("bound minecraft token did not validate: %d %s", vv.Code, vv.Body.String())
	}

	rebound := rotateBoundAccess0128(t, h, bound, "Minecraft trust device B")
	if rebound.BindingEpoch <= bound.BindingEpoch {
		t.Fatalf("re-bind did not advance epoch: before=%d after=%d", bound.BindingEpoch, rebound.BindingEpoch)
	}
	validate = httptest.NewRequest(http.MethodPost, "/authserver/validate", strings.NewReader(`{"accessToken":"`+mcToken+`","clientToken":"trust-client"}`))
	vv = httptest.NewRecorder()
	h.ServeHTTP(vv, validate)
	if vv.Code != http.StatusForbidden {
		t.Fatalf("minecraft token survived parent device re-bind: %d %s", vv.Code, vv.Body.String())
	}
}

func TestServerBridgeTrust0127LiveBindingAndRiskEnforcement(t *testing.T) {
	h := testServer(t)
	admin := loginAdmin(t, h)

	identity := newTestBridgeNodeIdentity0142(t)
	rv := registerTestBridgeNode0142(t, h, admin, "trust-0127", "Trust 0127", "paper", "demo-project", "vanilla", identity)
	if rv.Code != http.StatusCreated {
		t.Fatalf("register server=%d %s", rv.Code, rv.Body.String())
	}

	access, _ := deviceTrustLogin0121(t, h, "bridge-trust-0127")
	bound := bindAccessToken0127(t, h, access, "Bridge trust device A")
	issueJoin := func() {
		join := httptest.NewRequest(http.MethodPost, "/api/v1/session/join", strings.NewReader(`{"protocolVersion":2,"serverId":"trust-0127","projectId":"demo-project","profileId":"vanilla","channel":"stable","username":"TrustPlayer"}`))
		join.Header.Set("Authorization", "Bearer "+bound.Access)
		join.Header.Set("Content-Type", "application/json")
		join.Header.Set("User-Agent", "NeverLauncher-DeviceTrust-Test/0.12.1")
		join.RemoteAddr = "203.0.113.10:4242"
		jv := httptest.NewRecorder()
		h.ServeHTTP(jv, join)
		if jv.Code != http.StatusOK {
			t.Fatalf("trusted bridge join=%d %s", jv.Code, jv.Body.String())
		}
	}
	issueJoin()

	validateJoin := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/validate-join", strings.NewReader(`{"protocolVersion":2,"serverId":"trust-0127","username":"TrustPlayer","projectId":"demo-project","profileId":"vanilla","channel":"stable"}`))
		req.Header.Set("Content-Type", "application/json")
		signBridgeNodeRequest0142(t, req, "trust-0127", identity)
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out
	}
	first := validateJoin()
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"policy":"session-device-risk-v1"`) {
		t.Fatalf("trusted validate-join=%d %s", first.Code, first.Body.String())
	}

	issueJoin()
	channelMismatch := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/validate-join", strings.NewReader(`{"protocolVersion":2,"serverId":"trust-0127","username":"TrustPlayer","projectId":"demo-project","profileId":"vanilla","channel":"beta"}`))
	channelMismatch.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, channelMismatch, "trust-0127", identity)
	cm := httptest.NewRecorder()
	h.ServeHTTP(cm, channelMismatch)
	if cm.Code != http.StatusForbidden || !strings.Contains(cm.Body.String(), "channel_mismatch") {
		t.Fatalf("bridge accepted mismatched channel: %d %s", cm.Code, cm.Body.String())
	}

	// A player-side network/UA drift creates an enforceable risk decision. The
	// plugin request itself must not overwrite that player risk with server IP/UA.
	drift := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	drift.Header.Set("Authorization", "Bearer "+bound.Access)
	drift.Header.Set("User-Agent", "NeverLauncher-Risk-Drift/0.12.7")
	drift.RemoteAddr = "203.0.113.77:4300"
	dv := httptest.NewRecorder()
	h.ServeHTTP(dv, drift)
	if dv.Code != http.StatusOK {
		t.Fatalf("risk drift request=%d %s", dv.Code, dv.Body.String())
	}
	denied := validateJoin()
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "session_step_up_required") {
		t.Fatalf("bridge ignored live risk policy: %d %s", denied.Code, denied.Body.String())
	}
}

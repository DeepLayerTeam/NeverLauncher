package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerBridgeProtocol0191CapabilitiesNegotiation(t *testing.T) {
	handler := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server-bridge/capabilities?protocols=3,2&features=protocol.capability-negotiation,protocol.feature-flags,protocol.rolling-upgrade-v2,security.ed25519-node-requests,security.single-use-node-nonce,integrity.sha256,join.one-time,handoff.one-time,topology.runtime-learned", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("capabilities v3 => %d %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, want := range []string{`"release":"ServerBridge 3"`, `"negotiatedProtocolVersion":3`, `"legacyProtocolV2Supported":true`, `"protocol.capability-negotiation":true`, `"protocol.feature-flags":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("capabilities v3 missing %s: %s", want, body)
		}
	}

	// A client that understands Protocol v3 but not its required feature-flags
	// must negotiate v2 when it also offers v2; the backend never pretends the
	// incomplete v3 contract is safe.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/server-bridge/capabilities?protocols=3,2&features=security.ed25519-node-requests,integrity.sha256,join.one-time", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"negotiatedProtocolVersion":2`) {
		t.Fatalf("capabilities v2 fallback => %d %s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/server-bridge/capabilities?protocols=99&features=protocol.capability-negotiation,protocol.feature-flags", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUpgradeRequired || !strings.Contains(res.Body.String(), "serverbridge_no_compatible_protocol") {
		t.Fatalf("incompatible capabilities offer => %d %s", res.Code, res.Body.String())
	}
}

func TestServerBridgeProtocol0191SeparateV2V3Contracts(t *testing.T) {
	v2, err := decodeBridgeHeartbeat0191(strings.NewReader(`{"protocolVersion":2,"serverId":"node","serverType":"paper","pluginVersion":"0.19.0","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	if err != nil || v2.ProtocolVersion != 2 || len(v2.Features) != 0 {
		t.Fatalf("v2 heartbeat contract decode failed: req=%+v err=%v", v2, err)
	}
	if ok, reason := validateBridgeProtocolFeatures0191(v2.ProtocolVersion, v2.Features); !ok {
		t.Fatalf("v2 rolling-upgrade contract rejected: %s", reason)
	}

	if _, err := decodeBridgeHeartbeat0191(strings.NewReader(`{"protocolVersion":2,"features":["protocol.feature-flags"],"serverId":"node","serverType":"paper","pluginVersion":"0.19.0","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)); err == nil {
		t.Fatal("Protocol v2 contract must reject Protocol v3 feature field")
	}

	v3, err := decodeBridgeHeartbeat0191(strings.NewReader(`{"protocolVersion":3,"features":["protocol.feature-flags","protocol.capability-negotiation"],"serverId":"node","serverType":"paper","pluginVersion":"0.19.1","pluginSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
	if err != nil || v3.ProtocolVersion != 3 {
		t.Fatalf("v3 heartbeat contract decode failed: req=%+v err=%v", v3, err)
	}
	if ok, reason := validateBridgeProtocolFeatures0191(v3.ProtocolVersion, v3.Features); !ok {
		t.Fatalf("v3 heartbeat contract rejected: %s", reason)
	}

	missingFlags, err := decodeBridgeValidateJoin0191(strings.NewReader(`{"protocolVersion":3,"features":["protocol.capability-negotiation"],"serverId":"node","username":"Player","pluginVersion":"0.19.1","pluginSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := validateBridgeProtocolFeatures0191(missingFlags.ProtocolVersion, missingFlags.Features); ok || reason != "serverbridge_v3_required_features_missing" {
		t.Fatalf("incomplete v3 contract must fail closed: ok=%v reason=%s", ok, reason)
	}

	if ok, reason := validateBridgeProtocolFeatures0191(serverBridgeProtocolV3, []string{serverBridgeFeatureCapabilityNegotiation, serverBridgeFeatureFlags, "future.unknown-feature"}); ok || reason != "serverbridge_v3_feature_unsupported" {
		t.Fatalf("unknown v3 feature must fail closed: ok=%v reason=%s", ok, reason)
	}

	handoff, err := decodeBridgeHandoff0191(strings.NewReader(`{"protocolVersion":3,"features":["protocol.capability-negotiation","protocol.feature-flags"],"username":"Player","targetServer":"paper-main"}`))
	if err != nil || handoff.ProtocolVersion != 3 || handoff.TargetServer != "paper-main" {
		t.Fatalf("v3 handoff contract decode failed: req=%+v err=%v", handoff, err)
	}
}

func TestServerBridgeProtocol0191HeartbeatRollingUpgrade(t *testing.T) {
	handler := testServer(t)
	adminToken := loginAdmin(t, handler)
	identity := newTestBridgeNodeIdentity0142(t)
	res := registerTestBridgeNode0142(t, handler, adminToken, "paper-0191", "Paper 0191", "paper", "demo-project", "vanilla", identity)
	if res.Code != http.StatusCreated {
		t.Fatalf("register => %d %s", res.Code, res.Body.String())
	}

	// Existing 0.19.0/v2 bridge remains accepted during a rolling deploy.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/paper-0191/heartbeat", strings.NewReader(`{"protocolVersion":2,"serverId":"paper-0191","serverType":"paper","pluginVersion":"0.19.0","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	req.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, req, "paper-0191", identity)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"protocolVersion":2`) {
		t.Fatalf("v2 rolling heartbeat => %d %s", res.Code, res.Body.String())
	}

	// v3 without negotiated feature flags is rejected.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/paper-0191/heartbeat", strings.NewReader(`{"protocolVersion":3,"features":["protocol.capability-negotiation"],"serverId":"paper-0191","serverType":"paper","pluginVersion":"0.19.1","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	req.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, req, "paper-0191", identity)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUpgradeRequired || !strings.Contains(res.Body.String(), "serverbridge_v3_required_features_missing") {
		t.Fatalf("incomplete v3 heartbeat => %d %s", res.Code, res.Body.String())
	}

	// Fully negotiated v3 becomes the active node protocol.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/server-bridge/servers/paper-0191/heartbeat", strings.NewReader(`{"protocolVersion":3,"features":["protocol.capability-negotiation","protocol.feature-flags","protocol.rolling-upgrade-v2","security.ed25519-node-requests","security.single-use-node-nonce","integrity.sha256","join.one-time","handoff.one-time","topology.runtime-learned"],"serverId":"paper-0191","serverType":"paper","pluginVersion":"0.19.1","pluginSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	req.Header.Set("Content-Type", "application/json")
	signBridgeNodeRequest0142(t, req, "paper-0191", identity)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"protocolVersion":3`) || !strings.Contains(res.Body.String(), `"protocol.feature-flags"`) {
		t.Fatalf("v3 heartbeat => %d %s", res.Code, res.Body.String())
	}
}

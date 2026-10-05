package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerBridgeGA0200ProtocolV3IsFrozen(t *testing.T) {
	if !serverBridgeV3Frozen0200() {
		t.Fatalf("Protocol v3 feature set drifted: got %s want %s", serverBridgeV3FeatureDigest0200(serverBridgeV3Features0191), serverBridgeV3FrozenFeatureDigest0200)
	}
	if got := serverBridgeProtocolMode0200(3); got != "ga-frozen" {
		t.Fatalf("Protocol v3 mode = %q", got)
	}
	if got := serverBridgeProtocolMode0200(2); got != "compatibility-deprecated" {
		t.Fatalf("Protocol v2 mode = %q", got)
	}
}

func TestServerBridgeGA0200ProtocolV2DeprecationHeaders(t *testing.T) {
	res := httptest.NewRecorder()
	markServerBridgeProtocolResponse0200(res, 2)
	if res.Header().Get("Deprecation") != "true" || res.Header().Get("X-NeverLauncher-ServerBridge-Migrate-To") != "3" {
		t.Fatalf("Protocol v2 response is missing deprecation/migration headers: %#v", res.Header())
	}
	if res.Header().Get("X-NeverLauncher-ServerBridge-Protocol") != "compatibility-deprecated" {
		t.Fatalf("unexpected protocol mode header: %q", res.Header().Get("X-NeverLauncher-ServerBridge-Protocol"))
	}
}

func TestServerBridgeGA0200OverviewAndPublicMatrix(t *testing.T) {
	handler := testServer(t)
	adminToken := loginAdmin(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server-bridge/overview", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("overview => %d %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, want := range []string{`"release":"ServerBridge 3 GA"`, `"status":"ga-frozen"`, `"v2Mode":"compatibility-deprecated"`, `"featureDigest":"` + serverBridgeV3FrozenFeatureDigest0200 + `"`, `"nodes":`, `"topology":`, `"control":`, `"audit":`} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview missing %s: %s", want, body)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/server-bridge/matrix", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("matrix => %d %s", res.Code, res.Body.String())
	}
	body = res.Body.String()
	for _, want := range []string{`"protocolV3Frozen":true`, `"protocolV2Mode":"compatibility-deprecated"`, `"migrationCommand":"nl server-bridge migrate-v3"`, `"id":"quilt"`, `"id":"sponge"`, `"id":"vanilla"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("matrix missing %s: %s", want, body)
		}
	}
}

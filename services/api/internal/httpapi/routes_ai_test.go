package httpapi

import (
	"net/http"
	"testing"
)

func TestAIGatewayDisabledAndUnauthorized121(t *testing.T) {
	h := testServer(t)
	for _, path := range []string{"/api/v1/ai/responses", "/api/v1/ai/usage", "/api/v1/admin/ai/usage"} {
		method, body := http.MethodGet, ""
		if path == "/api/v1/ai/responses" {
			method, body = http.MethodPost, `{"prompt":"test"}`
		}
		if res := request0211(t, h, method, path, "", body); res.Code != 401 {
			t.Fatalf("%s unauthenticated: %d", path, res.Code)
		}
	}
	token := loginAdmin(t, h)
	for _, path := range []string{"/api/v1/ai/responses", "/api/v1/ai/usage", "/api/v1/admin/ai/usage"} {
		method, body := http.MethodGet, ""
		if path == "/api/v1/ai/responses" {
			method, body = http.MethodPost, `{"prompt":"test"}`
		}
		if res := request0211(t, h, method, path, token, body); res.Code != 503 {
			t.Fatalf("%s disabled: %d %s", path, res.Code, res.Body.String())
		}
	}
}

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDesktopProfileServers0229ScopeAndPublicResponse(t *testing.T) {
	h := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/demo-project/profiles/vanilla/servers", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("catalog HTTP %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"items":`) {
		t.Fatalf("catalog empty format: %s", res.Body.String())
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("server catalog must not be cached")
	}
	for _, path := range []string{"/api/v1/projects/no-such-project/profiles/vanilla/servers", "/api/v1/projects/demo-project/profiles/no-such-profile/servers"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		res = httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusNotFound {
			t.Fatalf("%s => %d", path, res.Code)
		}
	}
}

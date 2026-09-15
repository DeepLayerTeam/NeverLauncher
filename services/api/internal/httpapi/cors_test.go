package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSPrefightUsesExplicitAllowlist(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), []string{"https://admin.example.com"})

	allowed := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
	allowed.Header.Set("Origin", "https://admin.example.com")
	allowedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d, want %d", allowedRecorder.Code, http.StatusNoContent)
	}
	if got := allowedRecorder.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.example.com" {
		t.Fatalf("allow origin = %q", got)
	}

	blocked := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
	blocked.Header.Set("Origin", "https://evil.example")
	blockedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusForbidden {
		t.Fatalf("blocked preflight status = %d, want %d", blockedRecorder.Code, http.StatusForbidden)
	}
	if got := blockedRecorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("blocked origin unexpectedly allowed: %q", got)
	}
}

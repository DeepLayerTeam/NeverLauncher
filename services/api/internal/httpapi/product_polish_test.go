package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
)

func TestClientIPDoesNotTrustForwardedHeadersByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/status", nil)
	req.RemoteAddr = "203.0.113.9:4567"
	req.Header.Set("X-Forwarded-For", "198.51.100.77")
	if got := resolveClientIP(req, &trustedProxySet{}); got != "203.0.113.9" {
		t.Fatalf("client IP spoofed through untrusted XFF: %q", got)
	}
}

func TestClientIPWalksTrustedProxyChainFromRight(t *testing.T) {
	trusted, err := newTrustedProxySet([]string{"10.0.0.0/8", "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/status", nil)
	req.RemoteAddr = "10.0.0.20:4567"
	req.Header.Set("X-Forwarded-For", "198.51.100.77, 10.0.0.10")
	if got := resolveClientIP(req, trusted); got != "198.51.100.77" {
		t.Fatalf("unexpected client IP: %q", got)
	}

	// If an untrusted hop injects an earlier address, the nearest untrusted hop
	// wins and the spoofed address on its left is ignored.
	req.Header.Set("X-Forwarded-For", "192.0.2.44, 198.51.100.88")
	if got := resolveClientIP(req, trusted); got != "198.51.100.88" {
		t.Fatalf("trusted chain accepted spoofed left-most IP: %q", got)
	}
}

func TestRateLimiterUsesResolvedClientIPAndAuthBudget(t *testing.T) {
	state := NewRuntimeState()
	state.RateLimiter = ratelimit.NewMemory()
	state.RateLimitEnabled = true
	state.RateLimitGlobalPerMinute = 100
	state.RateLimitAuthPerMinute = 2
	state.RateLimitFailClosed = true
	trusted, _ := newTrustedProxySet([]string{"10.0.0.0/8"})
	state.TrustedProxies = trusted
	s := Server{State: state}

	handler := withTrustedProxyResolution(s.withRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})), trusted)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/auth/login", nil)
		req.RemoteAddr = "10.0.0.5:5000"
		req.Header.Set("X-Forwarded-For", "198.51.100.90")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if i < 2 && res.Code != http.StatusNoContent {
			t.Fatalf("request %d unexpectedly limited: %d %s", i+1, res.Code, res.Body.String())
		}
		if i == 2 && res.Code != http.StatusTooManyRequests {
			t.Fatalf("third auth request not limited: %d %s", res.Code, res.Body.String())
		}
	}
}

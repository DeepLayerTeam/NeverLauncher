package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
)

func TestServerBridgePublicMatrix0149IsCompleteAndHonestAboutCoverage(t *testing.T) {
	rows := serverBridgeMatrixPlatforms0149("0.14.9")
	if len(rows) != 11 {
		t.Fatalf("expected 11 ServerBridge matrix rows, got %d", len(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.ID] {
			t.Fatalf("duplicate matrix target %q", row.ID)
		}
		seen[row.ID] = true
		if row.ProtocolVersion != 2 || row.Installation != "drop-in-zero-patch" || !row.CryptographicIdentity || !row.ArtifactIntegrity || !row.OneTimeJoin {
			t.Fatalf("incomplete security capability row: %+v", row)
		}
		if row.Role == "proxy" && !row.HandoffSource {
			t.Fatalf("proxy %s is not handoff source", row.ID)
		}
		if row.Role == "backend" && !row.HandoffTarget {
			t.Fatalf("backend %s is not handoff target", row.ID)
		}
		if row.ID == "bukkit" && row.Coverage != "build-compatibility" {
			t.Fatalf("Bukkit coverage must be transparent: %+v", row)
		}
	}
}

func TestServerBridgeRateLimitUsesDedicatedDistributedBudget0149(t *testing.T) {
	state := NewRuntimeState()
	state.RateLimiter = ratelimit.NewMemory()
	state.RateLimitEnabled = true
	state.RateLimitGlobalPerMinute = 100
	state.RateLimitAuthPerMinute = 100
	state.RateLimitServerBridgePerMinute = 1
	state.RateLimitFailClosed = true
	s := Server{State: state}
	h := s.withRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/server-bridge/validate-join", bytes.NewReader([]byte(`{}`)))
		req.RemoteAddr = "198.51.100.42:1234"
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if got := res.Header().Get("X-RateLimit-Scope"); got != "serverbridge" {
			t.Fatalf("scope=%q", got)
		}
		if i == 0 && res.Code != http.StatusNoContent {
			t.Fatalf("first request code=%d", res.Code)
		}
		if i == 1 && res.Code != http.StatusTooManyRequests {
			t.Fatalf("second request code=%d", res.Code)
		}
	}
}

func TestSignedServerBridgeBodyCeiling0149(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/server-bridge/validate-join", bytes.NewReader(bytes.Repeat([]byte("x"), serverBridgeNodeMaxBody0142+1)))
	_, err := readAndRestoreNodeRequestBody0142(req)
	authErr, ok := err.(*bridgeNodeAuthError0142)
	if !ok || authErr.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 bridge auth error, got %#v", err)
	}
}

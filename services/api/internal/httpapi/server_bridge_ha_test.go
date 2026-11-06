package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/ratelimit"
)

func TestServerBridgePublicMatrix0149IsCompleteAndHonestAboutCoverage(t *testing.T) {
	rows := serverBridgeMatrixPlatforms0149("0.19.2")
	if len(rows) != 14 {
		t.Fatalf("Ожидалось 14 строк матрицы ServerBridge, получено %d", len(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.ID] {
			t.Fatalf("Повторяющаяся цель матрицы %q", row.ID)
		}
		seen[row.ID] = true
		if row.ProtocolVersion != serverBridgeProtocolV3 || len(row.SupportedProtocolVersions) != 2 || row.SupportedProtocolVersions[0] != serverBridgeProtocolV3 || row.SupportedProtocolVersions[1] != serverBridgeProtocolV2 || row.Installation != "drop-in-zero-patch" || !row.CryptographicIdentity || !row.ArtifactIntegrity || !row.OneTimeJoin {
			t.Fatalf("Неполная строка возможностей безопасности: %+v", row)
		}
		if row.Role == "proxy" && !row.HandoffSource {
			t.Fatalf("Прокси %s не является источником передачи соединения", row.ID)
		}
		if row.Role == "backend" && !row.HandoffTarget {
			t.Fatalf("Backend %s не является целью передачи соединения", row.ID)
		}
		if row.ID == "bukkit" && row.Coverage != "build-compatibility" {
			t.Fatalf("Покрытие Bukkit должно быть отображено явно: %+v", row)
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
		t.Fatalf("Ожидалась ошибка авторизации моста 413, получено %#v", err)
	}
}

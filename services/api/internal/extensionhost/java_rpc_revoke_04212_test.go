package extensionhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// The direct Go->JVM path must enforce the same durable revocation decision
// as capability HTTP requests. The fake loopback callback counts attempted
// deliveries; revoked calls must never reach it, even with a live callback.
func TestJavaDirectRPCRejectsRevokedExtension04212(t *testing.T) {
	ctx := context.Background()
	host, repo, st := liveTrustFixture04210(t)
	attempts := 0
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"protocolVersion": "1.0", "requestId": "bad", "ok": true,
			"result": map[string]any{"state": "RUNNING"},
		})
	}))
	defer callback.Close()
	st.javaHost = true
	st.callbackURL = callback.URL
	st.callbackToken = "callback-secret"
	host.processes[st.key.String()] = st

	// Before the revocation the callback is reached (its deliberately wrong
	// request ID makes the RPC fail after delivery).
	_, _ = host.CallJavaRPC0304(ctx, st.key, "health", nil)
	if attempts != 1 {
		t.Fatalf("active host callback not reached: %d", attempts)
	}
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{
		ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := host.CallJavaRPC0304(ctx, st.key, "command.invoke", json.RawMessage(`{"command":"dangerous"}`))
	if err == nil || !strings.Contains(err.Error(), "trust") {
		t.Fatalf("revoked direct RPC not rejected: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("revoked callback delivered to JVM: %d", attempts)
	}
	st.mu.Lock()
	stopped := st.expectedStop
	st.mu.Unlock()
	if !stopped {
		t.Fatal("supervisor did not initiate revocation stop")
	}
}

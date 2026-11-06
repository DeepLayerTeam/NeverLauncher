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

// Прямой путь Go→JVM обязан применять то же устойчивое решение об отзыве, что и
// HTTP-запросы возможностей. Фиктивный callback на loopback считает попытки
// доставки; отозванные вызовы никогда не должны доходить до него даже при живом
// callback.
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

	// До отзыва вызывается callback; умышленно неправильный request ID вызывает
	// ошибку RPC после доставки.
	_, _ = host.CallJavaRPC0304(ctx, st.key, "health", nil)
	if attempts != 1 {
		t.Fatalf("Обратный вызов активного хоста не выполнен: %d", attempts)
	}
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{
		ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := host.CallJavaRPC0304(ctx, st.key, "command.invoke", json.RawMessage(`{"command":"dangerous"}`))
	if err == nil || !strings.Contains(err.Error(), "trust") {
		t.Fatalf("Не отклонён прямой RPC с отозванными правами: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("Обратный вызов с отозванными правами доставлен в JVM: %d", attempts)
	}
	st.mu.Lock()
	stopped := st.expectedStop
	st.mu.Unlock()
	if !stopped {
		t.Fatal("Контроллер не инициировал остановку после отзыва прав")
	}
}

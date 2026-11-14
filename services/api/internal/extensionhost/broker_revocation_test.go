package extensionhost

import (
	"context"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestBrokerResponseRevocation04312(t *testing.T) {
	host, repo, st := liveTrustFixture04210(t)
	ctx := context.Background()
	req := capabilityRequest{Key: "sample"}
	if err := host.revalidateCapability04312(ctx, st, "runtime.storage.get", req); err != nil {
		t.Fatalf("Начальное предоставление права отклонено: %v", err)
	}
	if err := repo.RevokeExtensionPermission(ctx, st.key.ExtensionID, "global", "", "storage:read"); err != nil {
		t.Fatal(err)
	}
	if err := host.revalidateCapability04312(ctx, st, "runtime.storage.get", req); err == nil || !strings.Contains(err.Error(), "Отозвано") {
		t.Fatalf("Результат раскрыт после отзыва разрешения: %v", err)
	}
	if err := host.revalidateCapability04312(ctx, st, "unknown.privilege", req); err == nil {
		t.Fatal("Ошибочно разрешена неизвестная возможность")
	}
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := host.revalidateCapability04312(ctx, st, "extension.self", req); err == nil {
		t.Fatal("После аварийного отключения ошибочно разрешён ответ с метаданными")
	}
}

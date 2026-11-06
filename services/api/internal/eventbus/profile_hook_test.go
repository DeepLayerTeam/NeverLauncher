package eventbus

import (
	"context"
	"errors"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Проверяет настоящий устойчивый Go EventBus, область подписки и семантику
// запрета.
func TestProfileBeforeSaveVeto0495(t *testing.T) {
	_, bus := eventRepo0206(t)
	ctx := context.Background()
	if _, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "profile.before-save", Mode: "sync"}); err != nil {
		t.Fatal(err)
	}
	profile := model.Profile{ID: "p1", ProjectID: "project1", Loader: "fabric", LoaderVersion: "0.16.0"}
	bus.SetDispatcher(&testDispatcher0206{reject: true})
	if err := bus.BeforeProfileSave(ctx, "owner", "update", profile); !errors.Is(err, ErrHookRejected) {
		t.Fatalf("запрет обработчика события не применён: %v", err)
	}
	bus.SetDispatcher(nil)
	if err := bus.BeforeProfileSave(ctx, "owner", "update", profile); err == nil {
		t.Fatal("отсутствие диспетчера обработчиков событий должно блокировать изменение")
	}
	bus.SetDispatcher(&testDispatcher0206{})
	if err := bus.BeforeProfileSave(ctx, "owner", "update", profile); err != nil {
		t.Fatalf("Корректный профиль ошибочно отклонён: %v", err)
	}
}

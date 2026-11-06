package eventbus

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

type permanentDispatcher0487 struct{ calls int }

func (d *permanentDispatcher0487) DeliverExtensionEvent(context.Context, model.ExtensionEventSubscription, model.ExtensionEvent) error {
	d.calls++
	return ErrPermanentDelivery
}
func (d *permanentDispatcher0487) DeliverExtensionHook(context.Context, model.ExtensionEventSubscription, model.ExtensionEvent) (model.ExtensionHookResult, error) {
	return model.ExtensionHookResult{OK: false}, nil
}
func TestJavaPermanentRejectionDeadLettersImmediately0487(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "permanent", Source: "java", Payload: map[string]any{"k": 1}})
	if err != nil {
		t.Fatal(err)
	}
	d := &permanentDispatcher0487{}
	bus.SetDispatcher(d)
	bus.processBatch(ctx)
	items, err := repo.ListExtensionEventDeadLetters(ctx, "test.events", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Attempts != 1 || d.calls != 1 {
		t.Fatalf("deadletters=%+v calls=%d", items, d.calls)
	}
	// Повтор того же ключа идемпотентности не должен снова ставить завершённый
	// элемент в очередь.
	_, inserted, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "permanent", Source: "java", Payload: map[string]any{"k": 1}})
	if err != nil || inserted {
		t.Fatalf("повторная доставка добавлена=%v; ошибка=%v", inserted, err)
	}
	bus.processBatch(ctx)
	if d.calls != 1 {
		t.Fatal("сообщение из очереди неуспешных доставок выполнено повторно")
	}
}
func TestJavaSyncPoliciesFailClosed0487(t *testing.T) {
	_, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "release.before-publish", Mode: "sync"})
	if err != nil {
		t.Fatal(err)
	}
	bus.SetDispatcher(&permanentDispatcher0487{})
	err = bus.DispatchSync(ctx, PublishInput{Type: "release.before-publish", ProjectID: "p1", AggregateType: "release", AggregateID: "r1", IdempotencyKey: "blocked", Payload: map[string]any{"signed": false}})
	if !errors.Is(err, ErrHookRejected) {
		t.Fatalf("ожидалось отклонение: %v", err)
	}
	cancelled, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	err = bus.DispatchSync(cancelled, PublishInput{Type: "release.before-publish", ProjectID: "p1", AggregateType: "release", AggregateID: "r1", IdempotencyKey: "cancelled", Payload: map[string]any{}})
	if err == nil {
		t.Fatal("отменённый обработчик события ошибочно принят")
	}
}

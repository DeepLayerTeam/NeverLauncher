package eventbus

import (
	"context"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Pending deliveries and subscriptions belong to the repository, not to a
// particular Bus worker. A new worker must resume them after a graceful stop.
func TestBusWorkerRestartResumesDurableDelivery0423(t *testing.T) {
	repo, first := eventRepo0206(t)
	ctx := context.Background()
	sub, err := first.Subscribe(ctx, model.ExtensionEventSubscription{
		ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: model.ExtensionEventModeAsync,
	})
	if err != nil {
		t.Fatal(err)
	}
	event, inserted, err := first.Publish(ctx, PublishInput{
		Type: "project.saved", ProjectID: "p1", AggregateType: "project",
		AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "restart-0423",
		Source: "test", Payload: map[string]any{"generation": 1},
	})
	if err != nil || !inserted {
		t.Fatalf("publish inserted=%v: %v", inserted, err)
	}
	first.Start(ctx) // no dispatcher registered, delivery must remain pending
	first.Close()
	resumed, err := New(Config{WorkerInterval: 5 * time.Millisecond, LeaseDuration: time.Second}, repo)
	if err != nil {
		t.Fatal(err)
	}
	subs, err := resumed.Subscriptions(ctx, sub.ExtensionID, sub.Scope, sub.ScopeID)
	if err != nil || len(subs) != 1 || subs[0].ID != sub.ID {
		t.Fatalf("subscription lost on worker restart: %+v %v", subs, err)
	}
	dispatcher := &testDispatcher0206{}
	resumed.SetDispatcher(dispatcher)
	resumed.Start(ctx)
	defer resumed.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dispatcher.mu.Lock()
		got := append([]int64(nil), dispatcher.delivered...)
		dispatcher.mu.Unlock()
		if len(got) > 0 {
			if len(got) != 1 || got[0] != event.Sequence {
				t.Fatalf("recovery changed delivery identity: %v", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("pending delivery not resumed by replacement EventBus worker")
}

type blockingDispatch0423 struct {
	started chan struct{}
	release chan struct{}
}

func (d *blockingDispatch0423) DeliverExtensionEvent(ctx context.Context, _ model.ExtensionEventSubscription, _ model.ExtensionEvent) error {
	select {
	case d.started <- struct{}{}:
	default:
	}
	select {
	case <-d.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (d *blockingDispatch0423) DeliverExtensionHook(context.Context, model.ExtensionEventSubscription, model.ExtensionEvent) (model.ExtensionHookResult, error) {
	return model.ExtensionHookResult{OK: true}, nil
}

// A worker must not pre-lease future events while handling another callback.
// Otherwise a slow first callback can exhaust the remaining leases before
// execution begins, making duplicate delivery possible on a second API node.
func TestEventBatchLeasesAtDispatchTime0423(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{
		ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: model.ExtensionEventModeAsync,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2"} {
		if _, _, err := bus.Publish(ctx, PublishInput{
			Type: "project.saved", ProjectID: id, AggregateType: "project",
			AggregateID: id, OrderingKey: "project:" + id,
			IdempotencyKey: "batch-" + id, Source: "test", Payload: map[string]any{"id": id},
		}); err != nil {
			t.Fatal(err)
		}
	}
	dispatcher := &blockingDispatch0423{started: make(chan struct{}, 1), release: make(chan struct{})}
	bus.SetDispatcher(dispatcher)
	finished := make(chan struct{})
	go func() { bus.processBatch(ctx); close(finished) }()
	select {
	case <-dispatcher.started:
	case <-time.After(time.Second):
		t.Fatal("first callback never started")
	}
	// Other workers must be able to claim the independent second ordering key:
	// it has not been preleased by our blocked callback worker.
	pending, err := repo.LeaseExtensionEventDeliveries(ctx, 1, time.Now().Add(time.Second))
	if err != nil || len(pending) != 1 || pending[0].Event.AggregateID != "p2" {
		close(dispatcher.release)
		t.Fatalf("second delivery was pre-leased: %+v err=%v", pending, err)
	}
	if err := repo.CompleteExtensionEventDelivery(ctx, pending[0].Delivery.ID, pending[0].Delivery.LeaseToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	close(dispatcher.release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("worker failed to finish")
	}
}

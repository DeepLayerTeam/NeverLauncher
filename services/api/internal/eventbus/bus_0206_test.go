package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type testDispatcher0206 struct {
	mu        sync.Mutex
	delivered []int64
	failures  int
	reject    bool
	hookDelay time.Duration
}

func (d *testDispatcher0206) DeliverExtensionEvent(ctx context.Context, sub model.ExtensionEventSubscription, e model.ExtensionEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failures > 0 {
		d.failures--
		return errors.New("synthetic delivery failure")
	}
	d.delivered = append(d.delivered, e.Sequence)
	return nil
}
func (d *testDispatcher0206) DeliverExtensionHook(ctx context.Context, sub model.ExtensionEventSubscription, e model.ExtensionEvent) (model.ExtensionHookResult, error) {
	if d.hookDelay > 0 {
		select {
		case <-ctx.Done():
			return model.ExtensionHookResult{}, ctx.Err()
		case <-time.After(d.hookDelay):
		}
	}
	if d.reject {
		return model.ExtensionHookResult{OK: false, Message: "blocked"}, nil
	}
	return model.ExtensionHookResult{OK: true}, nil
}

func eventRepo0206(t *testing.T) (*repository.MemoryRepository, *Bus) {
	t.Helper()
	repo := repository.NewMemoryRepository("http://localhost")
	_, err := repo.SaveExtensionVersion(context.Background(), model.ExtensionManifest{SchemaVersion: "2.0", ID: "test.events", Name: "Events", Version: "1.0.0", Publisher: "tests", API: "1", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "bin/ext"}}, Permissions: []string{"events:subscribe", "events:sync", "project:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.TransitionExtensionInstall(context.Background(), model.ExtensionLifecycleTransition{ExtensionID: "test.events", Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, Operation: "enable", Source: "test", ExpectedGeneration: 0}); err != nil {
		t.Fatal(err)
	}
	bus, err := New(Config{WorkerInterval: 10 * time.Millisecond, LeaseDuration: 200 * time.Millisecond, BaseRetry: 10 * time.Millisecond, MaxRetry: 20 * time.Millisecond, MaxAttempts: 3, BatchSize: 10, HookTimeout: 50 * time.Millisecond}, repo)
	if err != nil {
		t.Fatal(err)
	}
	return repo, bus
}

func TestEventBusIdempotencyAndOrdering0206(t *testing.T) {
	_, bus := eventRepo0206(t)
	ctx := context.Background()
	sub, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID == 0 {
		t.Fatal("subscription id not assigned")
	}
	first, inserted, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "same", Source: "test", Payload: map[string]any{"v": 1}})
	if err != nil || !inserted {
		t.Fatalf("first publish inserted=%v err=%v", inserted, err)
	}
	again, inserted, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "same", Source: "test", Payload: map[string]any{"v": 1}})
	if err != nil || inserted || again.Sequence != first.Sequence {
		t.Fatalf("idempotent publish mismatch inserted=%v err=%v", inserted, err)
	}
	if _, _, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "same", Source: "test", Payload: map[string]any{"v": 2}}); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	_, _, _ = bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "second", Source: "test", Payload: map[string]any{"v": 2}})
	d := &testDispatcher0206{failures: 1}
	bus.SetDispatcher(d)
	bus.Start(ctx)
	defer bus.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		n := len(d.delivered)
		seq := append([]int64(nil), d.delivered...)
		d.mu.Unlock()
		if n == 2 {
			if seq[0] >= seq[1] {
				t.Fatalf("delivery order=%v", seq)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("events were not delivered")
}

func TestSyncHookReject0206(t *testing.T) {
	_, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.before-save", Mode: "sync"})
	if err != nil {
		t.Fatal(err)
	}
	bus.SetDispatcher(&testDispatcher0206{reject: true})
	err = bus.DispatchSync(ctx, PublishInput{Type: "project.before-save", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "hook-1", Source: "test", Payload: map[string]any{"id": "p1"}})
	if !errors.Is(err, ErrHookRejected) {
		t.Fatalf("expected hook rejection, got %v", err)
	}
}

func TestAsyncDeliveryMovesToDLQ0206(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "dlq", Source: "test", Payload: map[string]any{"v": 1}})
	if err != nil {
		t.Fatal(err)
	}
	bus.SetDispatcher(&testDispatcher0206{failures: 99})
	bus.Start(ctx)
	defer bus.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items, _ := repo.ListExtensionEventDeadLetters(ctx, "test.events", 10)
		if len(items) == 1 {
			if items[0].Attempts != 3 {
				t.Fatalf("attempts=%d", items[0].Attempts)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("delivery was not moved to DLQ")
}

func TestSyncHookTimeout0206(t *testing.T) {
	_, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.before-save", Mode: "sync"})
	if err != nil {
		t.Fatal(err)
	}
	bus.SetDispatcher(&testDispatcher0206{hookDelay: 250 * time.Millisecond})
	err = bus.DispatchSync(ctx, PublishInput{Type: "project.before-save", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "hook-timeout", Source: "test", Payload: ProjectPayload{Action: "update", Actor: "admin", Project: model.Project{ID: "p1"}}})
	if !errors.Is(err, ErrHookTimeout) {
		t.Fatalf("expected hook timeout, got %v", err)
	}
}

func TestSubscriptionUnsubscribeStopsFutureDelivery0206(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	sub, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "before-unsubscribe", Source: "test", Payload: map[string]any{"v": 1}}); err != nil {
		t.Fatal(err)
	}
	if err = bus.Unsubscribe(ctx, sub.ID, sub.ExtensionID, sub.Scope, sub.ScopeID); err != nil {
		t.Fatal(err)
	}
	items, err := repo.LeaseExtensionEventDeliveries(ctx, 10, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("unsubscribed delivery remained leaseable: %d", len(items))
	}
}

func TestTypedProjectPayloadKeepsActionAndActor0206(t *testing.T) {
	e, err := buildEvent0206(PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "typed-payload", Source: "test", Payload: ProjectPayload{Action: "update", Actor: "admin", Project: model.Project{ID: "p1"}}})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(e.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "update" || payload["actor"] != "admin" {
		t.Fatalf("typed payload lost action/actor: %s", e.Payload)
	}
}

func TestSubscriptionPauseResumePreservesDurableDelivery0206(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "paused", Source: "test", Payload: map[string]any{"v": 1}}); err != nil {
		t.Fatal(err)
	}
	if err := bus.SetSubscriptionsEnabled(ctx, "test.events", "global", "", false); err != nil {
		t.Fatal(err)
	}
	items, err := repo.LeaseExtensionEventDeliveries(ctx, 10, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("paused subscription leased %d deliveries", len(items))
	}
	if err := bus.SetSubscriptionsEnabled(ctx, "test.events", "global", "", true); err != nil {
		t.Fatal(err)
	}
	items, err = repo.LeaseExtensionEventDeliveries(ctx, 10, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Event.IdempotencyKey != "paused" {
		t.Fatalf("durable delivery was not resumed: %#v", items)
	}
}

func TestDeliveryLeaseFencingRejectsStaleAck0206(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "lease-fence", Source: "test", Payload: map[string]any{"v": 1}}); err != nil {
		t.Fatal(err)
	}
	first, err := repo.LeaseExtensionEventDeliveries(ctx, 1, time.Now().Add(10*time.Millisecond))
	if err != nil || len(first) != 1 || first[0].Delivery.LeaseToken == "" {
		t.Fatalf("first lease: items=%#v err=%v", first, err)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := repo.LeaseExtensionEventDeliveries(ctx, 1, time.Now().Add(time.Second))
	if err != nil || len(second) != 1 || second[0].Delivery.LeaseToken == "" || second[0].Delivery.LeaseToken == first[0].Delivery.LeaseToken {
		t.Fatalf("second lease: items=%#v err=%v", second, err)
	}
	if err := repo.CompleteExtensionEventDelivery(ctx, first[0].Delivery.ID, first[0].Delivery.LeaseToken, time.Now()); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("stale lease ACK should conflict, got %v", err)
	}
	if err := repo.CompleteExtensionEventDelivery(ctx, second[0].Delivery.ID, second[0].Delivery.LeaseToken, time.Now()); err != nil {
		t.Fatalf("current lease ACK failed: %v", err)
	}
}

func TestDisabledInstallPausesAsyncAndSyncWithoutDroppingBacklog0206(t *testing.T) {
	repo, bus := eventRepo0206(t)
	ctx := context.Background()
	_, err := bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.saved", Mode: "async"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bus.Subscribe(ctx, model.ExtensionEventSubscription{ExtensionID: "test.events", Scope: "global", EventType: "project.before-save", Mode: "sync"})
	if err != nil {
		t.Fatal(err)
	}
	state, err := repo.GetExtensionInstallState(ctx, "test.events", "global", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: "test.events", Scope: "global", DesiredVersion: state.DesiredVersion, CurrentVersion: state.CurrentVersion, DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled, Enabled: false, Operation: "disable", Source: "test", ExpectedGeneration: state.Generation}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bus.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "while-disabled", Source: "test", Payload: map[string]any{"v": 1}}); err != nil {
		t.Fatal(err)
	}
	items, err := repo.LeaseExtensionEventDeliveries(ctx, 10, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("disabled installation leased async events: %d", len(items))
	}
	bus.SetDispatcher(&testDispatcher0206{reject: true})
	if err := bus.DispatchSync(ctx, PublishInput{Type: "project.before-save", ProjectID: "p1", AggregateType: "project", AggregateID: "p1", OrderingKey: "project:p1", IdempotencyKey: "disabled-hook", Source: "test", Payload: map[string]any{"id": "p1"}}); err != nil {
		t.Fatalf("disabled installation should not run sync hook: %v", err)
	}
	state, err = repo.GetExtensionInstallState(ctx, "test.events", "global", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: "test.events", Scope: "global", DesiredVersion: state.DesiredVersion, CurrentVersion: state.CurrentVersion, DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, Operation: "enable", Source: "test", ExpectedGeneration: state.Generation}); err != nil {
		t.Fatal(err)
	}
	items, err = repo.LeaseExtensionEventDeliveries(ctx, 10, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 || items[0].Event.IdempotencyKey != "while-disabled" {
		t.Fatalf("durable backlog did not resume after enable: %#v", items)
	}
}

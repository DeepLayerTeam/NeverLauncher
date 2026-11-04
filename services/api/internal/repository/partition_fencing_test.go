package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Покрывает совместимую с production семантику памяти, используемую
// сериализованной плоскостью управления SQLite. Устаревший токен не может
// завершить, провалить или освободить владение после истечения аренды, даже если
// его ещё никто не перехватил.
func TestExpiredMutationAndJobFences0514(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("http://127.0.0.1")
	lease, err := r.AcquireDurableScopeLease(ctx, "package:0514", "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.durableMu.Lock()
	old := r.durableScopeLeases[lease.ScopeKey]
	old.ExpiresAt = time.Now().Add(-time.Second)
	r.durableScopeLeases[lease.ScopeKey] = old
	r.durableMu.Unlock()
	if err := r.ReleaseDurableScopeLease(ctx, lease.ScopeKey, lease.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired scope token released lease: %v", err)
	}
	newLease, err := r.AcquireDurableScopeLease(ctx, lease.ScopeKey, "worker-b", time.Minute)
	if err != nil || newLease.FencingToken <= lease.FencingToken {
		t.Fatalf("new fence not monotonic: %#v %v", newLease, err)
	}
	if _, err := r.RenewDurableScopeLease(ctx, lease.ScopeKey, lease.LeaseToken, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale owner renewed newer fence: %v", err)
	}
	job, _, err := r.EnqueueDurableJob(ctx, model.DurableJob{
		Kind: "package-publish", ActorType: "user", ActorID: "operator",
		Action: "release:publish", ResourceType: "package", ResourceID: "pkg0514",
		IdempotencyKey: "partition-0514", Payload: []byte(`{"test":true}`),
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldJob, err := r.LeaseDurableJob(ctx, job.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.durableMu.Lock()
	expiredJob := r.durableJobs[job.ID]
	expiredJob.LeaseExpiresAt = time.Now().Add(-time.Second)
	r.durableJobs[job.ID] = expiredJob
	r.durableMu.Unlock()
	if _, err := r.FailDurableJob(ctx, job.ID, oldJob.LeaseToken, "late", time.Second); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired owner failed job: %v", err)
	}
	if _, err := r.TerminateDurableJob(ctx, job.ID, oldJob.LeaseToken, model.DurableJobStatusFailed, "late"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired owner terminated job: %v", err)
	}
	claimed, err := r.LeaseDurableJob(ctx, job.ID, "worker-b", time.Minute)
	if err != nil || claimed.LeaseFence <= oldJob.LeaseFence {
		t.Fatalf("worker-b must take over with higher fence: %+v %v", claimed, err)
	}
}

func TestExpiredExhaustedWorkBecomesTerminal0514(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("http://127.0.0.1")
	job, _, err := r.EnqueueDurableJob(ctx, model.DurableJob{
		Kind: "partition-exhausted-0514", ActorType: "user", ActorID: "operator",
		Action: "release:publish", ResourceType: "package", ResourceID: "pkg-exhausted",
		IdempotencyKey: "partition-exhausted", MaxAttempts: 1,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := r.LeaseDurableJob(ctx, job.ID, "worker-a", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.durableMu.Lock()
	expired := r.durableJobs[job.ID]
	expired.LeaseExpiresAt = time.Now().Add(-time.Second)
	r.durableJobs[job.ID] = expired
	id := "out-exhausted-0514"
	r.durableOutbox[id] = model.DurableOutboxEvent{
		ID: id, Status: model.OutboxStatusRunning, LeaseToken: "expired-token",
		LeaseOwner: "worker-a", AttemptCount: 1, MaxAttempts: 1,
		LeaseExpiresAt: time.Now().Add(-time.Second),
	}
	r.durableMu.Unlock()
	if _, err := r.LeaseDurableJobs(ctx, job.Kind, "worker-b", 8, time.Minute); err != nil {
		t.Fatal(err)
	}
	current, err := r.GetDurableJob(ctx, job.ID)
	if err != nil || current.Status != model.DurableJobStatusDead || current.LeaseToken != "" {
		t.Fatalf("exhausted job remains runnable: %+v %v", current, err)
	}
	if _, err := r.FailDurableJob(ctx, job.ID, leased.LeaseToken, "late", 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("exhausted worker changed terminal job: %v", err)
	}
	if _, err := r.ClaimOutboxEvents(ctx, "worker-b", 8, time.Minute); err != nil {
		t.Fatal(err)
	}
	r.durableMu.Lock()
	currentEvent := r.durableOutbox[id]
	r.durableMu.Unlock()
	if currentEvent.Status != model.OutboxStatusDead || currentEvent.LeaseToken != "" {
		t.Fatalf("exhausted outbox event remains runnable: %+v", currentEvent)
	}
}

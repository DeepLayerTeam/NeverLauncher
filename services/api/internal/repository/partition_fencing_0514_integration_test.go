//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Executed with two independent SQL pools against a real PostgreSQL instance.
// Directly expiring rows simulates a partition/reconnect without depending on
// wall-clock sleeps or trusting the worker's clock.
func TestPostgresPartitionFencing0514(t *testing.T) {
	a, b, ctx := openDurablePostgres0213(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scope := "partition:0514:" + suffix
	first, err := a.AcquireDurableScopeLease(ctx, scope, "node-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var dbNow time.Time
	if err := b.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		t.Fatal(err)
	}
	if d := first.ExpiresAt.Sub(dbNow); d < 55*time.Second || d > 65*time.Second {
		t.Fatalf("scope lease expiry is not based on PostgreSQL time: %s", d)
	}
	if _, err := b.AcquireDurableScopeLease(ctx, scope, "node-b", time.Minute); !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("dual owner on live PostgreSQL lease: %v", err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE durable_scope_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE scope_key=$1`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RenewDurableScopeLease(ctx, scope, first.LeaseToken, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale renewal accepted: %v", err)
	}
	second, err := b.AcquireDurableScopeLease(ctx, scope, "node-b", time.Minute)
	if err != nil || second.FencingToken <= first.FencingToken {
		t.Fatalf("stale takeover did not advance fence: %+v %v", second, err)
	}
	if err := a.ReleaseDurableScopeLease(ctx, scope, first.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("old owner released new lease: %v", err)
	}

	job, _, err := a.EnqueueDurableJob(ctx, model.DurableJob{
		Kind: "partition-0514", ActorType: "user", ActorID: "operator", Action: "test:partition",
		ProjectID: "test-" + suffix, ResourceType: "package", ResourceID: "package-" + suffix,
		IdempotencyKey: "partition-" + suffix, Payload: []byte(`{"test":true}`),
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := a.LeaseDurableJob(ctx, job.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE durable_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.FailDurableJob(ctx, job.ID, leased.LeaseToken, "stale", 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired worker failed job: %v", err)
	}
	if _, err := a.TerminateDurableJob(ctx, job.ID, leased.LeaseToken, model.DurableJobStatusFailed, "stale"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired worker terminated job: %v", err)
	}
	newJob, err := b.LeaseDurableJob(ctx, job.ID, "worker-b", time.Minute)
	if err != nil || newJob.LeaseFence <= leased.LeaseFence {
		t.Fatalf("worker-b did not replace expired owner: %+v %v", newJob, err)
	}
	if _, err := a.FailDurableJob(ctx, job.ID, leased.LeaseToken, "late", 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale worker mutated successor job: %v", err)
	}
	if _, err := b.FailDurableJob(ctx, job.ID, newJob.LeaseToken, "retry", 0); err != nil {
		t.Fatalf("current owner could not fail/requeue its job: %v", err)
	}

	outID := "out_partition_0514_" + suffix
	_, err = a.db.ExecContext(ctx, `INSERT INTO event_outbox(id,event_type,aggregate_type,aggregate_id,idempotency_key,payload) VALUES($1,'package.published','release',$2,$3,'{}'::jsonb)`, outID, job.ID, outID)
	if err != nil {
		t.Fatal(err)
	}
	firstOut, err := a.ClaimOutboxEvents(ctx, "worker-a", 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var firstToken string
	var firstFence int64
	for _, event := range firstOut {
		if event.ID == outID {
			firstToken, firstFence = event.LeaseToken, event.LeaseFence
		}
	}
	if firstToken == "" {
		t.Fatal("new outbox event not claimed")
	}
	if _, err = a.db.ExecContext(ctx, `UPDATE event_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, outID); err != nil {
		t.Fatal(err)
	}
	if err := a.CompleteOutboxEvent(ctx, outID, firstToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired owner completed outbox event: %v", err)
	}
	secondOut, err := b.ClaimOutboxEvents(ctx, "worker-b", 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var successor string
	for _, event := range secondOut {
		if event.ID == outID {
			if event.LeaseFence <= firstFence || event.LeaseToken == firstToken {
				t.Fatalf("outbox claim did not advance fence: %+v", event)
			}
			successor = event.LeaseToken
		}
	}
	if successor == "" {
		t.Fatal("second worker did not reclaim outbox event")
	}
	if err := a.FailOutboxEvent(ctx, outID, firstToken, "late", 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("old worker changed successor outbox event: %v", err)
	}
	if err := b.CompleteOutboxEvent(ctx, outID, successor); err != nil {
		t.Fatalf("current worker could not complete outbox event: %v", err)
	}
}

func TestPostgresExpiredLeaseFailClosed0514(t *testing.T) {
	a, _, ctx := openDurablePostgres0213(t)
	scope := fmt.Sprintf("expire:0514:%d", time.Now().UnixNano())
	lease, err := a.AcquireDurableScopeLease(ctx, scope, "node-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE durable_scope_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE scope_key=$1`, scope); err != nil {
		t.Fatal(err)
	}
	if err := a.ReleaseDurableScopeLease(context.Background(), scope, lease.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired scope release must fail: %v", err)
	}
}

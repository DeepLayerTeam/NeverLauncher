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

// Выполняется через два независимых SQL-пула на настоящем PostgreSQL. Прямое
// завершение срока строк имитирует разделение сети и переподключение без ожиданий
// по настенным часам и доверия к часам воркера.
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
		t.Fatalf("срок действия аренды области не основан на времени PostgreSQL: %s", d)
	}
	if _, err := b.AcquireDurableScopeLease(ctx, scope, "node-b", time.Minute); !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("действующая аренда PostgreSQL имеет двух владельцев: %v", err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE durable_scope_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE scope_key=$1`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RenewDurableScopeLease(ctx, scope, first.LeaseToken, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("принято продление устаревшей аренды: %v", err)
	}
	second, err := b.AcquireDurableScopeLease(ctx, scope, "node-b", time.Minute)
	if err != nil || second.FencingToken <= first.FencingToken {
		t.Fatalf("захват после истечения аренды не увеличил эпоху защиты: %+v %v", second, err)
	}
	if err := a.ReleaseDurableScopeLease(ctx, scope, first.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("прежний владелец освободил новую аренду: %v", err)
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
		t.Fatalf("обработчик с истёкшей арендой пометил задание ошибочным: %v", err)
	}
	if _, err := a.TerminateDurableJob(ctx, job.ID, leased.LeaseToken, model.DurableJobStatusFailed, "stale"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("обработчик с истёкшей арендой завершил задание: %v", err)
	}
	newJob, err := b.LeaseDurableJob(ctx, job.ID, "worker-b", time.Minute)
	if err != nil || newJob.LeaseFence <= leased.LeaseFence {
		t.Fatalf("второй обработчик не заменил владельца с истёкшей арендой: %+v %v", newJob, err)
	}
	if _, err := a.FailDurableJob(ctx, job.ID, leased.LeaseToken, "late", 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("устаревший обработчик изменил задание преемника: %v", err)
	}
	if _, err := b.FailDurableJob(ctx, job.ID, newJob.LeaseToken, "retry", 0); err != nil {
		t.Fatalf("текущий владелец не смог завершить задание с ошибкой либо поставить его в очередь повторно: %v", err)
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
		t.Fatal("новое событие исходящей очереди не захвачено")
	}
	if _, err = a.db.ExecContext(ctx, `UPDATE event_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, outID); err != nil {
		t.Fatal(err)
	}
	if err := a.CompleteOutboxEvent(ctx, outID, firstToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("владелец с истёкшей арендой завершил событие исходящей очереди: %v", err)
	}
	secondOut, err := b.ClaimOutboxEvents(ctx, "worker-b", 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var successor string
	for _, event := range secondOut {
		if event.ID == outID {
			if event.LeaseFence <= firstFence || event.LeaseToken == firstToken {
				t.Fatalf("захват исходящего события не увеличил эпоху защиты: %+v", event)
			}
			successor = event.LeaseToken
		}
	}
	if successor == "" {
		t.Fatal("второй обработчик не перехватил событие исходящей очереди")
	}
	if err := a.FailOutboxEvent(ctx, outID, firstToken, "late", 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("прежний обработчик изменил событие исходящей очереди преемника: %v", err)
	}
	if err := b.CompleteOutboxEvent(ctx, outID, successor); err != nil {
		t.Fatalf("текущий обработчик не смог завершить событие исходящей очереди: %v", err)
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
		t.Fatalf("освобождение области с истёкшей арендой должно завершаться ошибкой: %v", err)
	}
}

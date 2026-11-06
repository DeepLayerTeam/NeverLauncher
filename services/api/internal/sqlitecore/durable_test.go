package sqlitecore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func newDurableJob(key string) model.DurableJob {
	return model.DurableJob{Kind: "release", ActorType: "user", ActorID: "operator", Action: "publish", ResourceType: "release", ResourceID: "r1", IdempotencyKey: key, Payload: []byte(`{"hello":"world"}`), MaxAttempts: 3}
}
func newDurableEvent(key string) model.DurableOutboxEvent {
	return model.DurableOutboxEvent{EventType: "release.published", AggregateType: "release", AggregateID: "r1", IdempotencyKey: key, Payload: []byte(`{"release":"r1"}`), MaxAttempts: 3}
}

func TestDurableJobIdempotencyConcurrentLeaseAndCrash(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	j, created, e := r.EnqueueDurableJob(ctx, newDurableJob("request-123"), 0)
	if e != nil || !created {
		t.Fatalf("ошибка постановки в очередь: %v %v", created, e)
	}
	duplicate, created, e := r.EnqueueDurableJob(ctx, newDurableJob("request-123"), 0)
	if e != nil || created || j.ID != duplicate.ID {
		t.Fatalf("ошибка устранения дубликатов: %v %v", created, e)
	}
	other := newDurableJob("request-123")
	other.Payload = []byte(`{"hello":"different"}`)
	if _, _, e = r.EnqueueDurableJob(ctx, other, 0); !errors.Is(e, ErrDurableIdempotency) {
		t.Fatalf("Другая полезная нагрузка не была отклонена: %v", e)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	var leased model.DurableJob
	var mu sync.Mutex
	for k := 0; k < 24; k++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := r.LeaseDurableJob(ctx, j.ID, fmt.Sprint("worker-", i), time.Second)
			if e == nil {
				winners.Add(1)
				mu.Lock()
				leased = c
				mu.Unlock()
			} else if !errors.Is(e, ErrDurableLeaseBusy) {
				t.Errorf("ошибка захвата задания: %v", e)
			}
		}(k)
	}
	wg.Wait()
	if winners.Load() != 1 || leased.LeaseFence != 1 || leased.AttemptCount != 1 {
		t.Fatalf("победителей=%d, захват=%+v", winners.Load(), leased)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	state, e := r.GetDurableJob(ctx, j.ID)
	if e != nil || state.Status != "running" || state.LeaseToken != leased.LeaseToken {
		t.Fatalf("аренда потеряна после перезапуска: %+v %v", state, e)
	}
	// После истечения аренды воркер становится устаревшим и не должен завершать
	// работу, даже если оставался живым во время реального сбоя процесса.
	time.Sleep(1100 * time.Millisecond)
	next, e := r.LeaseDurableJob(ctx, j.ID, "worker-recover", time.Second)
	if e != nil || next.LeaseFence != 2 || next.AttemptCount != 2 {
		t.Fatalf("аренда при восстановлении: %+v %v", next, e)
	}
	if _, e = r.CompleteOperationJob(ctx, j.ID, leased.LeaseToken, nil); !errors.Is(e, ErrDurableLeaseLost) {
		t.Fatalf("устаревший обработчик зафиксировал изменения: %v", e)
	}
	done, e := r.CompleteOperationJob(ctx, j.ID, next.LeaseToken, []byte(`{"ok":true}`))
	if e != nil || done.Status != "succeeded" {
		t.Fatalf("завершение: %+v %v", done, e)
	}
	attempts, e := r.ListOperationAttempts(ctx, j.ID)
	if e != nil || len(attempts) != 2 || attempts[0].Status != "expired" || attempts[1].Status != "succeeded" {
		t.Fatalf("попытки: %+v %v", attempts, e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestDurableRetryDeadLetter(t *testing.T) {
	r, _ := openTest(t)
	ctx := context.Background()
	j := newDurableJob("retry")
	j.MaxAttempts = 2
	j, _, e := r.EnqueueDurableJob(ctx, j, 0)
	if e != nil {
		t.Fatal(e)
	}
	a, e := r.LeaseDurableJob(ctx, j.ID, "w", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	state, e := r.FailDurableJob(ctx, j.ID, a.LeaseToken, "temporary", 0)
	if e != nil || state.Status != "pending" {
		t.Fatalf("повторная попытка: %v %+v", e, state)
	}
	b, e := r.LeaseDurableJob(ctx, j.ID, "w", time.Second)
	if e != nil || b.LeaseFence != 2 {
		t.Fatalf("повторный захват: %v %+v", e, b)
	}
	state, e = r.FailDurableJob(ctx, j.ID, b.LeaseToken, "fatal", 0)
	if e != nil || state.Status != "dead" {
		t.Fatalf("очередь необработанных сообщений: %v %+v", e, state)
	}
	if _, e = r.LeaseDurableJob(ctx, j.ID, "other", time.Second); !errors.Is(e, ErrDurableLeaseBusy) {
		t.Fatalf("захвачено окончательно отклонённое задание: %v", e)
	}
}
func TestScopeFencingAndAtomicOutbox(t *testing.T) {
	r, _ := openTest(t)
	ctx := context.Background()
	j, _, e := r.EnqueueDurableJob(ctx, newDurableJob("fenced"), 0)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := r.LeaseDurableJob(ctx, j.ID, "worker", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	lease, e := r.AcquireDurableScopeLease(ctx, "release:r1", "worker", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.AcquireDurableScopeLease(ctx, "release:r1", "intruder", time.Second); !errors.Is(e, ErrDurableLeaseBusy) {
		t.Fatalf("аренда захвачена другим владельцем: %v", e)
	}
	// Некорректное событие должно откатывать всю бизнес-операцию и обновление
	// задачи.
	eBad := newDurableEvent("bad")
	eBad.Payload = []byte(`{bad json`)
	_, e = r.CommitFencedJob(ctx, j.ID, worker.LeaseToken, lease.ScopeKey, lease.LeaseToken, lease.FencingToken, nil, func(q sqlitedurable.Executor) error {
		_, er := q.ExecContext(ctx, `CREATE TABLE durable_application_marker(id TEXT PRIMARY KEY)`)
		return er
	}, []model.DurableOutboxEvent{eBad})
	if e == nil {
		t.Fatal("зафиксировано недопустимое событие")
	}
	markerExists := false
	_ = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var n int
		er := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name='durable_application_marker'`).Scan(&n)
		markerExists = n > 0
		return er
	})
	if markerExists {
		t.Fatal("изменение применено частично")
	}
	event := newDurableEvent("evt-1")
	done, e := r.CommitFencedJob(ctx, j.ID, worker.LeaseToken, lease.ScopeKey, lease.LeaseToken, lease.FencingToken, []byte(`{"applied":true}`), func(q sqlitedurable.Executor) error {
		_, er := q.ExecContext(ctx, `CREATE TABLE durable_application_marker(id TEXT PRIMARY KEY)`)
		if er != nil {
			return er
		}
		_, er = q.ExecContext(ctx, `INSERT INTO durable_application_marker VALUES('committed')`)
		return er
	}, []model.DurableOutboxEvent{event})
	if e != nil || done.Status != "succeeded" {
		t.Fatalf("фиксация изменений: %v %+v", e, done)
	}
	queued, e := r.ClaimOutboxEvents(ctx, "sender", 1, time.Second)
	if e != nil || len(queued) != 1 || queued[0].IdempotencyKey != "evt-1" {
		t.Fatalf("исходящая очередь: %v %+v", e, queued)
	}
	if e = r.CompleteOutboxEvent(ctx, queued[0].ID, queued[0].LeaseToken); e != nil {
		t.Fatal(e)
	}
	if _, e = r.CommitFencedJob(ctx, j.ID, worker.LeaseToken, lease.ScopeKey, lease.LeaseToken, lease.FencingToken, nil, func(sqlitedurable.Executor) error { return nil }, nil); !errors.Is(e, ErrDurableLeaseLost) {
		t.Fatalf("повторное завершение: %v", e)
	}
	if e = r.ReleaseDurableScopeLease(ctx, lease.ScopeKey, lease.LeaseToken); e != nil {
		t.Fatal(e)
	}
	successor, e := r.AcquireDurableScopeLease(ctx, lease.ScopeKey, "replacement", time.Second)
	if e != nil || successor.FencingToken != lease.FencingToken+1 {
		t.Fatalf("защита от устаревшего владельца не сработала: %+v %v", successor, e)
	}
	if _, e = r.RenewDurableScopeLease(ctx, lease.ScopeKey, lease.LeaseToken, time.Second); !errors.Is(e, ErrDurableLeaseLost) {
		t.Fatalf("старая блокировка была продлена: %v", e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestOutboxAtLeastOnceRestartAndIdempotentDelivery(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	ev, created, e := r.EnqueueOutboxEvent(ctx, newDurableEvent("retry-event"))
	if e != nil || !created {
		t.Fatal(e)
	}
	again, created, e := r.EnqueueOutboxEvent(ctx, newDurableEvent("retry-event"))
	if e != nil || created || again.ID != ev.ID {
		t.Fatalf("устранение дубликатов: %+v %v", again, e)
	}
	batch, e := r.ClaimOutboxEvents(ctx, "sender-1", 1, time.Second)
	if e != nil || len(batch) != 1 {
		t.Fatalf("Захват: %+v %v", batch, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	time.Sleep(1100 * time.Millisecond)
	next, e := r.ClaimOutboxEvents(ctx, "sender-2", 1, time.Second)
	if e != nil || len(next) != 1 || next[0].LeaseFence != 2 {
		t.Fatalf("повторная доставка: %+v %v", next, e)
	}
	if e = r.CompleteOutboxEvent(ctx, ev.ID, batch[0].LeaseToken); !errors.Is(e, ErrDurableLeaseLost) {
		t.Fatalf("Устаревший пакет доставки ошибочно принят: %v", e)
	}
	if e = r.CompleteOutboxEvent(ctx, ev.ID, next[0].LeaseToken); e != nil {
		t.Fatal(e)
	}
	state, e := r.GetOutboxEvent(ctx, ev.ID)
	if e != nil || state.Status != "delivered" {
		t.Fatalf("событие: %+v %v", state, e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestSQLiteUpgrade324To325WithoutLosingPriorCore(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	project(t, r)
	profile(t, r)
	// Создайте точную прежнюю схему без таблиц миграции 325, сохраняя
	// существующие строки ядра и изменяя user_version.
	e := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		for _, table := range []string{"durable_job_attempts", "durable_jobs", "durable_outbox", "durable_scope_leases"} {
			if _, er := q.ExecContext(ctx, "DROP TABLE "+table); er != nil {
				return er
			}
		}
		_, er := q.ExecContext(ctx, "PRAGMA user_version=324")
		return er
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	counts, e := r.Count(ctx)
	if e != nil || counts["projects"] != 1 || counts["profiles"] != 1 || counts["durable_jobs"] != 0 {
		t.Fatalf("количество записей после миграции: %v %v", counts, e)
	}
	if _, created, e := r.EnqueueDurableJob(ctx, newDurableJob("post-migration"), 0); e != nil || !created {
		t.Fatalf("в мигрированную БД не удаётся добавить задание: %v %v", created, e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestFencedCommitStaleEpochAfterReacquisition(t *testing.T) {
	r, _ := openTest(t)
	ctx := context.Background()
	j, _, e := r.EnqueueDurableJob(ctx, newDurableJob("stale-epoch"), 0)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := r.LeaseDurableJob(ctx, j.ID, "w", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	old, e := r.AcquireDurableScopeLease(ctx, "scope:stale", "w", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.ReleaseDurableScopeLease(ctx, old.ScopeKey, old.LeaseToken); e != nil {
		t.Fatal(e)
	}
	next, e := r.AcquireDurableScopeLease(ctx, old.ScopeKey, "w", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	_, e = r.CommitFencedJob(ctx, j.ID, worker.LeaseToken, old.ScopeKey, old.LeaseToken, old.FencingToken, nil, func(q sqlitedurable.Executor) error {
		_, er := q.ExecContext(ctx, `CREATE TABLE forbidden_side_effect(id TEXT)`)
		return er
	}, nil)
	if !errors.Is(e, ErrDurableLeaseLost) {
		t.Fatalf("зафиксированы изменения из устаревшей области доступа: %v", e)
	}
	if next.FencingToken != old.FencingToken+1 {
		t.Fatal("эпоха защиты от устаревших владельцев не увеличилась")
	}
	var n int
	e = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name='forbidden_side_effect'`).Scan(&n)
	})
	if e != nil || n != 0 {
		t.Fatalf("выполнено побочное действие устаревшего задания: число=%d %v", n, e)
	}
}

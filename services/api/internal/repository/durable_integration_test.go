//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func openDurablePostgres0213(t *testing.T) (*SQLRepository, *SQLRepository, context.Context) {
	t.Helper()
	dsn := os.Getenv("LAUNCHER_DURABLE_DSN")
	if dsn == "" {
		dsn = os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		dsn = os.Getenv("LAUNCHER_SERVERBRIDGE_HA_DSN")
	}
	if dsn == "" {
		t.Skip("Адрес подключения PostgreSQL для проверки надёжного сохранения не задан")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	open := func() *SQLRepository {
		r, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
		if !ok {
			t.Fatal("Репозиторий не является SQLRepository")
		}
		return r
	}
	a, b := open(), open()
	t.Cleanup(func() { _ = a.db.Close() })
	t.Cleanup(func() { _ = b.db.Close() })
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatalf("Ошибка применения миграций: %v", err)
	}
	return a, b, ctx
}

func TestDurableJobLeaseRecoversAcrossReplicaRestart0213(t *testing.T) {
	a, b, ctx := openDurablePostgres0213(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	job, created, err := a.EnqueueDurableJob(ctx, model.DurableJob{
		Kind: "package-publish", ActorType: "user", ActorID: "restart@example.test",
		Action: "package:publish", ProjectID: "project-" + suffix,
		ResourceType: "package", ResourceID: "package-" + suffix,
		IdempotencyKey: "restart-" + suffix,
		Payload:        []byte(`{"releaseId":"release-restart"}`),
	}, time.Hour)
	if err != nil || !created {
		t.Fatalf("Добавление в очередь: создано=%v, ошибка=%v", created, err)
	}
	first, err := a.LeaseDurableJob(ctx, job.ID, "api-a", 120*time.Millisecond)
	if err != nil {
		t.Fatalf("Первая аренда: %v", err)
	}
	if first.LeaseFence < 1 || first.LeaseToken == "" {
		t.Fatalf("Первая аренда ресурса не защищена ограничителем поколений: %+v", first)
	}
	if _, err := b.LeaseDurableJob(ctx, job.ID, "api-b", time.Second); !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("Вторая реплика захватила активную аренду ресурса, ошибка=%v", err)
	}
	time.Sleep(180 * time.Millisecond)
	recovered, err := b.LeaseDurableJob(ctx, job.ID, "api-b", time.Second)
	if err != nil {
		t.Fatalf("Просроченная аренда не восстановилась на второй реплике: %v", err)
	}
	if recovered.LeaseOwner != "api-b" || recovered.LeaseFence <= first.LeaseFence || recovered.LeaseToken == first.LeaseToken {
		t.Fatalf("При восстановлении аренды не изменился номер поколения: первая=%+v, восстановленная=%+v", first, recovered)
	}
	var abandonedStatus, abandonedError string
	if err := b.db.QueryRowContext(ctx, `SELECT status,error FROM durable_job_attempts WHERE job_id=$1 AND attempt=$2`, job.ID, first.AttemptCount).Scan(&abandonedStatus, &abandonedError); err != nil {
		t.Fatalf("Чтение брошенной попытки: %v", err)
	}
	if abandonedStatus != "failed" || abandonedError == "" {
		t.Fatalf("Брошенная попытка не закрыта при восстановлении после перезапуска: статус=%q, ошибка=%q", abandonedStatus, abandonedError)
	}
}

func TestDurableScopeLeaseHasSingleDistributedOwner0213(t *testing.T) {
	a, b, ctx := openDurablePostgres0213(t)
	scope := fmt.Sprintf("package:race-%d", time.Now().UnixNano())
	start := make(chan struct{})
	type outcome struct {
		lease model.DurableScopeLease
		err   error
	}
	out := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, contender := range []struct {
		repo  *SQLRepository
		owner string
	}{{a, "api-a"}, {b, "api-b"}} {
		wg.Add(1)
		go func(c struct {
			repo  *SQLRepository
			owner string
		}) {
			defer wg.Done()
			<-start
			lease, err := c.repo.AcquireDurableScopeLease(ctx, scope, c.owner, 3*time.Second)
			out <- outcome{lease: lease, err: err}
		}(contender)
	}
	close(start)
	wg.Wait()
	close(out)

	winners, busy := 0, 0
	var winner outcome
	for got := range out {
		switch {
		case got.err == nil:
			winner = got
			winners++
		case errors.Is(got.err, ErrLeaseBusy):
			busy++
		default:
			t.Fatalf("Неожиданная ошибка распределённой аренды: %v", got.err)
		}
	}
	if winners != 1 || busy != 1 {
		t.Fatalf("Ожидался один владелец распределённой аренды: победителей=%d, занятых=%d", winners, busy)
	}
	if err := a.ReleaseDurableScopeLease(ctx, scope, winner.lease.LeaseToken); err != nil {
		if err := b.ReleaseDurableScopeLease(ctx, scope, winner.lease.LeaseToken); err != nil {
			t.Fatalf("Освобождение выигравшей аренды: %v", err)
		}
	}
	next, err := b.AcquireDurableScopeLease(ctx, scope, "api-after-restart", 3*time.Second)
	if err != nil {
		t.Fatalf("Повторный захват после освобождения: %v", err)
	}
	if next.FencingToken <= winner.lease.FencingToken {
		t.Fatalf("Номер поколения не увеличился: первый=%d, следующий=%d", winner.lease.FencingToken, next.FencingToken)
	}
}

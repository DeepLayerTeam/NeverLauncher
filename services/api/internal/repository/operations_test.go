package repository

import (
	"context"
	"encoding/json"
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
	"time"
)

func newOperationFixture0217(t *testing.T) (*MemoryRepository, model.DurableJob) {
	t.Helper()
	r := NewMemoryRepository("http://localhost")
	ctx := context.Background()
	raw, _ := json.Marshal(map[string]string{"projectId": "demo-project", "channel": "stable", "toVersion": "1.0"})
	j, created, err := r.EnqueueDurableJob(ctx, model.DurableJob{Kind: "channel-rollback", ActorType: "user", ActorID: "alice", Action: "release:publish", ProjectID: "demo-project", ResourceType: "channel", ResourceID: "stable", IdempotencyKey: "request-1", Payload: raw}, time.Hour)
	if err != nil || !created {
		t.Fatalf("ошибка постановки в очередь: %v %v", created, err)
	}
	return r, j
}
func TestOperationsCancelBeforeLease0217(t *testing.T) {
	r, j := newOperationFixture0217(t)
	ctx := context.Background()
	cancelled, err := r.CancelOperationJob(ctx, j.ID, "alice")
	if err != nil || cancelled.Status != model.DurableJobStatusFailed {
		t.Fatalf("Отмена: %+v %v", cancelled, err)
	}
	if _, err = r.LeaseDurableJob(ctx, j.ID, "worker", time.Minute); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Отменённое задание получило блокировку выполнения: %v", err)
	}
	repeated, err := r.FindOperationByKey(ctx, j.Kind, j.ActorID, j.IdempotencyKey)
	if err != nil || repeated.ID != j.ID {
		t.Fatalf("Идемпотентный результат изменился после отмены: %+v %v", repeated, err)
	}
	retried, err := r.RetryOperationJob(ctx, j.ID)
	if err != nil || retried.Status != model.DurableJobStatusPending {
		t.Fatalf("Повтор: %+v %v", retried, err)
	}
	leased, err := r.LeaseDurableJob(ctx, j.ID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.CancelOperationJob(ctx, j.ID, "alice"); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Выполняемая операция отменена: %v", err)
	}
	result, _ := json.Marshal(map[string]string{"status": "succeeded"})
	completed, err := r.CompleteOperationJob(ctx, j.ID, leased.LeaseToken, result)
	if err != nil || completed.Status != model.DurableJobStatusSucceeded {
		t.Fatalf("завершение: %+v %v", completed, err)
	}
	if _, err = r.RetryOperationJob(ctx, j.ID); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Повторно запущено завершённое задание: %v", err)
	}
	history, err := r.ListOperationAttempts(ctx, j.ID)
	if err != nil || len(history) != 1 || history[0].Status != "succeeded" {
		t.Fatalf("Неожиданные попытки: %+v %v", history, err)
	}
}
func TestOperationsRetryPreservesHistoryAndFencing0217(t *testing.T) {
	r, j := newOperationFixture0217(t)
	ctx := context.Background()
	first, err := r.LeaseDurableJob(ctx, j.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := r.TerminateDurableJob(ctx, j.ID, first.LeaseToken, model.DurableJobStatusFailed, "test-network-failure")
	if err != nil || failed.Status != model.DurableJobStatusFailed {
		t.Fatalf("Завершение: %v %v", failed, err)
	}
	if _, err = r.RetryOperationJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	second, err := r.LeaseDurableJob(ctx, j.ID, "worker-2", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.LeaseFence <= first.LeaseFence || second.AttemptCount <= first.AttemptCount {
		t.Fatal("Повторный запуск использовал старое ограничение или номер попытки")
	}
	result, _ := json.Marshal(map[string]string{"status": "ok"})
	if _, err = r.CompleteOperationJob(ctx, j.ID, first.LeaseToken, result); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Устаревший исполнитель смог завершить операцию: %v", err)
	}
	if _, err = r.CompleteOperationJob(ctx, j.ID, second.LeaseToken, result); err != nil {
		t.Fatal(err)
	}
	attempts, err := r.ListOperationAttempts(ctx, j.ID)
	if err != nil || len(attempts) != 2 || attempts[0].Status != "failed" || attempts[1].Status != "succeeded" {
		t.Fatalf("Журнал попыток потерян: %+v %v", attempts, err)
	}
}

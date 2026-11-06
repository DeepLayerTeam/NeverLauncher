package repository

import (
	"context"
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
	"time"
)

func TestOperationalConfigCompareAndSwapAndRestore02111(t *testing.T) {
	ctx := context.Background()
	r := &MemoryRepository{}
	first, err := r.GetOperationalConfig(ctx)
	if err != nil || first.Revision != 1 {
		t.Fatalf("Начальное состояние: %+v %v", first, err)
	}
	edited := first.Settings
	edited.AuditDefaultPageSize = 50
	edited.AuditMaxPageSize = 60
	revision, err := r.SaveOperationalConfig(ctx, 1, edited, "admin", "change pagination", nil)
	if err != nil || revision.Revision != 2 {
		t.Fatalf("Сохранение: %+v %v", revision, err)
	}
	_, err = r.SaveOperationalConfig(ctx, 1, edited, "admin", "stale request", nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Ожидался конфликт ревизии CAS, получено %v", err)
	}
	previous := int64(1)
	restored, err := r.SaveOperationalConfig(ctx, 2, OperationalConfig{}, "admin", "restore previous", &previous)
	if err != nil || restored.Revision != 3 || restored.Settings != first.Settings || restored.RestoredFrom == nil || *restored.RestoredFrom != 1 {
		t.Fatalf("Восстановление: %+v %v", restored, err)
	}
	history, err := r.ListOperationalConfigRevisions(ctx, 10)
	if err != nil || len(history) != 3 || history[0].Revision != 3 || history[1].Revision != 2 || history[2].Revision != 1 {
		t.Fatalf("История: %+v %v", history, err)
	}
	missing := int64(49)
	_, err = r.SaveOperationalConfig(ctx, 3, OperationalConfig{}, "admin", "restore unknown", &missing)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Ожидалось отсутствие записи, получено %v", err)
	}
}
func TestOperationalConfigBounds02111(t *testing.T) {
	v := DefaultOperationalConfig()
	v.JobsMaxPageSize = 10
	if v.Validate() == nil {
		t.Fatal("Максимальное значение не должно быть меньше значения по умолчанию")
	}
	v = DefaultOperationalConfig()
	v.AuditLookbackDays = 0
	if v.Validate() == nil {
		t.Fatal("Период ретроспективы должен быть положительным")
	}
}
func TestAuditQueryFiltersAndPagination02111(t *testing.T) {
	now := time.Now().UTC()
	r := &MemoryRepository{}
	r.AddAuditEvent(model.AuditEvent{ID: "one", Actor: "admin", Action: "config:changed", Target: "revision:2", ReasonCode: "applied", CorrelationID: "cid-one", JobID: "job-a", CreatedAt: now})
	r.AddAuditEvent(model.AuditEvent{ID: "two", Actor: "operator", Action: "authorization:denied", Target: "project:a", ReasonCode: "insufficient_permissions", CorrelationID: "cid-two", CreatedAt: now.Add(-time.Hour)})
	q := AuditQuery{ReasonCode: "insufficient_permissions", Search: "cid-two", Limit: 10, Offset: 0}
	result, err := r.QueryAudit(context.Background(), q)
	if err != nil || result.Total != 1 || len(result.Items) != 1 || result.Items[0].ID != "two" {
		t.Fatalf("Фильтр: %+v %v", result, err)
	}
	q = AuditQuery{Limit: 1, Offset: 1}
	result, err = r.QueryAudit(context.Background(), q)
	if err != nil || result.Total != 2 || len(result.Items) != 1 || result.Items[0].ID != "two" {
		t.Fatalf("Страница: %+v %v", result, err)
	}
	q = AuditQuery{From: now.Add(-time.Minute), Limit: 10}
	result, err = r.QueryAudit(context.Background(), q)
	if err != nil || result.Total != 1 {
		t.Fatalf("Фильтр по дате: %+v %v", result, err)
	}
}

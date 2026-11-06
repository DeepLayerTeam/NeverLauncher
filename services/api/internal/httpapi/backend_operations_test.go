package httpapi

import (
	"testing"
	"time"
)

func TestBackendRecentClients0289(t *testing.T) {
	now := time.Now().UTC()
	clients := []authSessionRecord{
		{ID: "live", Status: "active", LastSeenAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		{ID: "stale", Status: "active", LastSeenAt: now.Add(-6 * time.Minute), ExpiresAt: now.Add(time.Hour)},
		{ID: "revoked", Status: "revoked", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "expired", Status: "active", LastSeenAt: now, ExpiresAt: now.Add(-time.Minute)},
	}
	got := backendRecentClients0289(clients, now, 5*time.Minute)
	if len(got) != 1 || got[0].SessionID != "live" {
		t.Fatalf("последние сеансы: %+v", got)
	}
}
func TestBackendLifecycle0289(t *testing.T) {
	lc, err := NewBackendLifecycle0289(false)
	if err != nil {
		t.Fatal(err)
	}
	if lc.ScheduleRestart() {
		t.Fatal("Запланирован перезапуск без контроля")
	}
	if lc.IsDraining() {
		t.Fatal("Экземпляр без контроля начал завершать соединения")
	}
	a, err := NewBackendLifecycle0289(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBackendLifecycle0289(true)
	if err != nil || a.InstanceID == b.InstanceID {
		t.Fatal("Повторно использован идентификатор Runtime")
	}
	if !a.ScheduleRestart() || a.ScheduleRestart() == true {
		t.Fatal("Запланирован повторный перезапуск")
	}
	select {
	case <-a.RestartRequested():
	case <-time.After(time.Second):
		t.Fatal("Перезапуск не отправлен на выполнение")
	}
}

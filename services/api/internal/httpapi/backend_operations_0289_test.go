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
		t.Fatalf("recent sessions=%+v", got)
	}
}
func TestBackendLifecycle0289(t *testing.T) {
	lc, err := NewBackendLifecycle0289(false)
	if err != nil {
		t.Fatal(err)
	}
	if lc.ScheduleRestart() {
		t.Fatal("unsupervised restart was scheduled")
	}
	if lc.IsDraining() {
		t.Fatal("unsupervised instance started draining")
	}
	a, err := NewBackendLifecycle0289(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBackendLifecycle0289(true)
	if err != nil || a.InstanceID == b.InstanceID {
		t.Fatal("runtime identity reused")
	}
	if !a.ScheduleRestart() || a.ScheduleRestart() == true {
		t.Fatal("duplicate restart scheduled")
	}
	select {
	case <-a.RestartRequested():
	case <-time.After(time.Second):
		t.Fatal("restart not dispatched")
	}
}

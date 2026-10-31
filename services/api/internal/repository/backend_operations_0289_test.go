package repository

import (
	"context"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
	"time"
)

func TestBackendRestartKey0289(t *testing.T) {
	a, err := BackendRestartKey0289("operator-1", "0123456789abcdef")
	if err != nil || len(a) != 64 {
		t.Fatalf("valid key: %v %s", err, a)
	}
	b, _ := BackendRestartKey0289("operator-2", "0123456789abcdef")
	if a == b {
		t.Fatal("separate actors share idempotency identity")
	}
	for _, key := range []string{"", "short", "0123456789abcd/xx", "0123456789abcdef?access_token=secret"} {
		if _, err := BackendRestartKey0289("operator", key); err == nil {
			t.Fatalf("unsafe key accepted: %q", key)
		}
	}
}
func TestBackendNoticeValidation0289(t *testing.T) {
	for _, tc := range []struct {
		user, body string
		ok         bool
	}{
		{"user-1", "Maintenance at 21:00", true}, {"user-1", "\n", false}, {"user-1", "line\x00break", false},
		{"", "Message", false}, {"u", "test", true},
	} {
		if err := ValidateBackendNotice0289(tc.user, tc.body); (err == nil) != tc.ok {
			t.Fatalf("notice validation user=%q body=%q err=%v", tc.user, tc.body, err)
		}
	}
}

func TestRecentMinecraftClients0289Memory(t *testing.T) {
	now := time.Now().UTC()
	repo := &MemoryRepository{minecraftSessions: []model.MinecraftSession{
		{ID: "a", UserID: "u", Status: "active", LastSeenAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		{ID: "old", Status: "active", LastSeenAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		{ID: "revoked", Status: "revoked", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)},
	}}
	got, err := repo.ListRecentMinecraftClients0289(context.Background(), now, 5*time.Minute)
	if err != nil || len(got) != 1 || got[0].SessionID != "a" {
		t.Fatalf("observed=%+v err=%v", got, err)
	}
}

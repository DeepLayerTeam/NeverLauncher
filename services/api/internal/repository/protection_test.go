package repository

import (
	"context"
	"testing"
	"time"
)

func TestProtectionBanLifecycle0298(t *testing.T) {
	r := NewMemoryRepository("")
	ctx := context.Background()
	now := time.Now().UTC()
	if _, ok, err := r.ActiveProtectionBan(ctx, "user", now); err != nil || ok {
		t.Fatalf("unexpected ban %v %v", ok, err)
	}
	if err := r.SetProtectionBan(ctx, ProtectionBan{UserID: "user", Reason: "abuse detected", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	b, ok, err := r.ActiveProtectionBan(ctx, "user", now)
	if err != nil || !ok || b.Reason != "abuse detected" {
		t.Fatalf("ban not enforced: %+v %v %v", b, ok, err)
	}
	if changed, err := r.RevokeProtectionBan(ctx, "user", "admin"); err != nil || !changed {
		t.Fatalf("unban %v %v", changed, err)
	}
	if _, ok, _ := r.ActiveProtectionBan(ctx, "user", now); ok {
		t.Fatal("unban ignored")
	}
	if err := r.SetProtectionBan(ctx, ProtectionBan{UserID: "user", Reason: "expired ban", Actor: "admin", ExpiresAt: func() *time.Time { x := now.Add(-time.Second); return &x }()}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.ActiveProtectionBan(ctx, "user", now); ok {
		t.Fatal("expired ban enforced")
	}
}

package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestHWIDMemoryObservationAppealAndRecovery0299(t *testing.T) {
	r := NewMemoryRepository("https://test.invalid")
	now := time.Now().UTC()
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "d1", UserID: "u1", Status: "active", TrustState: "verified"})
	r.deviceMu.Unlock()
	ctx := context.Background()
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	first, err := r.ObserveHWID0299(ctx, "u1", "d1", a, now)
	if err != nil || first.State != "recognized" {
		t.Fatalf("initial: %#v %v", first, err)
	}
	same, err := r.ObserveHWID0299(ctx, "u1", "d1", a, now.Add(time.Second))
	if err != nil || same.State != "recognized" {
		t.Fatalf("repeat: %#v %v", same, err)
	}
	changed, err := r.ObserveHWID0299(ctx, "u1", "d1", b, now.Add(2*time.Second))
	if err != nil || changed.State != "changed" || changed.Baseline != a || changed.Pending != b {
		t.Fatalf("changed: %#v %v", changed, err)
	}
	if _, err := r.ObserveHWID0299(ctx, "u2", "d1", a, now); err == nil {
		t.Fatal("cross-account observation allowed")
	}
	p := PublicHWIDState0299(changed)
	if strings.Contains(strings.Join([]string{p["state"].(string), p["deviceId"].(string)}, ":"), a) {
		t.Fatal("digest leaked")
	}
	appeal := HWIDAppeal0299{ID: "appeal-1", UserID: "u1", DeviceID: "d1", Reason: "Replaced motherboard", CreatedAt: now.Add(3 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, appeal); err != nil {
		t.Fatal(err)
	}
	if err := r.SubmitHWIDAppeal0299(ctx, appeal); err == nil {
		t.Fatal("duplicate pending appeal accepted")
	}
	resolved, err := r.ResolveHWIDAppeal0299(ctx, appeal.ID, "admin", "approved", now.Add(4*time.Second))
	if err != nil || resolved.Status != "approved" {
		t.Fatalf("appeal: %#v %v", resolved, err)
	}
	v, err := r.GetHWID0299(ctx, "u1", "d1", now.Add(5*time.Second))
	if err != nil || v.Baseline != b || v.Pending != "" || v.State != "recognized" {
		t.Fatalf("recovery: %#v %v", v, err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, appeal.ID, "admin", "approved", now.Add(6*time.Second)); err == nil {
		t.Fatal("appeal replay allowed")
	}
	if err := r.ForgetHWID0299(ctx, "u1", "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetHWID0299(ctx, "u1", "d1", now); err != ErrNotFound {
		t.Fatalf("forget: %v", err)
	}
	appeals, _ := r.ListHWIDAppeals0299(ctx, "u1")
	if len(appeals) != 0 {
		t.Fatal("appeals not deleted")
	}
}
func TestHWIDExpiryDoesNotLeaveActiveRisk0299(t *testing.T) {
	r := NewMemoryRepository("")
	now := time.Now().UTC()
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "d", UserID: "u", Status: "active"})
	r.deviceMu.Unlock()
	_, err := r.ObserveHWID0299(context.Background(), "u", "d", strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.GetHWID0299(context.Background(), "u", "d", now.Add(31*24*time.Hour)); err != ErrNotFound {
		t.Fatalf("expired hint active: %v", err)
	}
	if err = r.PruneHWID0299(context.Background(), now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(r.hwidObservations) != 0 {
		t.Fatal("expired hint retained")
	}
}

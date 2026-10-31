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

// A changed host signal is an untrusted hint, but once observed it must not be
// cleared by replaying the old hint. Review decisions are bound to a candidate.
func TestHWIDChangeIsStickyAndAppealCannotBeReplayed0433(t *testing.T) {
	r := NewMemoryRepository("https://test.invalid")
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "device", UserID: "owner", Status: "active", TrustState: "verified"})
	r.deviceMu.Unlock()
	ctx := context.Background()
	now := time.Now().UTC()
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	if _, err := r.ObserveHWID0299(ctx, "owner", "device", a, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ObserveHWID0299(ctx, "owner", "device", b, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	old, err := r.ObserveHWID0299(ctx, "owner", "device", a, now.Add(2*time.Second))
	if err != nil || old.State != "changed" || old.Pending != b || !old.UpdatedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("old baseline replay lifted or moved risk event: %#v %v", old, err)
	}
	first := HWIDAppeal0299{ID: "first", UserID: "owner", DeviceID: "device", Reason: "Changed mainboard", CreatedAt: now.Add(3 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, first); err != nil {
		t.Fatal(err)
	}
	next, err := r.ObserveHWID0299(ctx, "owner", "device", c, now.Add(4*time.Second))
	if err != nil || next.State != "changed" || next.Pending != c {
		t.Fatalf("new proposed hardware: %#v %v", next, err)
	}
	appeals, err := r.ListHWIDAppeals0299(ctx, "owner")
	if err != nil || len(appeals) != 1 || appeals[0].Status != "rejected" || appeals[0].Resolution != "superseded" {
		t.Fatalf("appeal was not invalidated: %#v %v", appeals, err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, "first", "admin", "approved", now.Add(5*time.Second)); err != ErrConflict {
		t.Fatalf("stale appeal approval: %v", err)
	}
	if _, err := r.ConfirmHWID0299(ctx, "owner", "device", b, now.Add(5*time.Second)); err != ErrNotFound {
		t.Fatalf("stale confirm accepted: %v", err)
	}
	second := HWIDAppeal0299{ID: "second", UserID: "owner", DeviceID: "device", Reason: "Another replacement", CreatedAt: now.Add(6 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, "second", "admin", "rejected", now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	afterReject, err := r.GetHWID0299(ctx, "owner", "device", now.Add(8*time.Second))
	if err != nil || afterReject.State != "changed" {
		t.Fatalf("rejection lifted risk: %#v %v", afterReject, err)
	}
	third := HWIDAppeal0299{ID: "third", UserID: "owner", DeviceID: "device", Reason: "Additional evidence", CreatedAt: now.Add(9 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, third); err != nil {
		t.Fatal(err)
	}
	confirmed, err := r.ConfirmHWID0299(ctx, "owner", "device", c, now.Add(10*time.Second))
	if err != nil || confirmed.State != "recognized" || confirmed.Baseline != c {
		t.Fatalf("owner confirmation: %#v %v", confirmed, err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, "third", "admin", "approved", now.Add(11*time.Second)); err != ErrConflict {
		t.Fatalf("owner-confirmed appeal still active: %v", err)
	}
	appeals, _ = r.ListHWIDAppeals0299(ctx, "owner")
	for _, a := range appeals {
		if a.ID == "third" && a.Resolution != "confirmed-by-owner" {
			t.Fatalf("appeal resolution lost: %#v", a)
		}
	}
	if _, err := r.ConfirmHWID0299(ctx, "owner", "device", c, now.Add(12*time.Second)); err != ErrNotFound {
		t.Fatalf("confirmation replay: %v", err)
	}
}

func TestHWIDPendingReplayAndForget0433(t *testing.T) {
	r := NewMemoryRepository("")
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "d", UserID: "u", Status: "active"})
	r.deviceMu.Unlock()
	ctx := context.Background()
	now := time.Now().UTC()
	a, b := strings.Repeat("1", 64), strings.Repeat("2", 64)
	_, _ = r.ObserveHWID0299(ctx, "u", "d", a, now)
	_, _ = r.ObserveHWID0299(ctx, "u", "d", b, now.Add(time.Second))
	for i := 0; i < 8; i++ {
		state, err := r.ObserveHWID0299(ctx, "u", "d", a, now.Add(time.Duration(i+2)*time.Second))
		if err != nil || state.State != "changed" || state.Pending != b {
			t.Fatalf("replay %d: %#v %v", i, state, err)
		}
	}
	if err := r.ForgetHWID0299(ctx, "u", "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetHWID0299(ctx, "u", "d", now); err != ErrNotFound {
		t.Fatalf("privacy forget failed: %v", err)
	}
}

//go:build !launcher_nopgx

package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHWIDRiskPostgresCrossReplica0299(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "hwid-u-" + suffix
	deviceID := "hwid-d-" + suffix
	_, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status) VALUES($1,$2,'HWID Test','player','active')`, userID, userID+"@example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	_, err = a.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,public_key,key_fingerprint) VALUES($1,$2,'HWID Test Device','test-key',$3)`, deviceID, userID, fmt.Sprintf("%064x", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hint1, hint2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	state, err := a.ObserveHWID0299(ctx, userID, deviceID, hint1, now)
	if err != nil || state.State != "recognized" {
		t.Fatalf("first: %#v %v", state, err)
	}
	state, err = b.ObserveHWID0299(ctx, userID, deviceID, hint2, now.Add(time.Second))
	if err != nil || state.State != "changed" {
		t.Fatalf("change: %#v %v", state, err)
	}
	got, err := a.GetHWID0299(ctx, userID, deviceID, now.Add(time.Second))
	if err != nil || got.State != "changed" {
		t.Fatalf("cross-replica: %#v %v", got, err)
	}
	appeal := HWIDAppeal0299{ID: "hwid-appeal-" + suffix, UserID: userID, DeviceID: deviceID, Reason: "Hardware replacement", CreatedAt: now.Add(2 * time.Second)}
	if err := a.SubmitHWIDAppeal0299(ctx, appeal); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ResolveHWIDAppeal0299(ctx, appeal.ID, "admin", "approved", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err = a.GetHWID0299(ctx, userID, deviceID, now.Add(4*time.Second))
	if err != nil || got.State != "recognized" || got.Baseline != hint2 {
		t.Fatalf("not recovered: %#v %v", got, err)
	}
	if err := b.ForgetHWID0299(ctx, userID, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetHWID0299(ctx, userID, deviceID, now); err != ErrNotFound {
		t.Fatalf("not deleted across replicas: %v", err)
	}
}

func TestHWIDPostgresStaleAppealAndHardwareChange0433(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, deviceID := "hwid-u-"+suffix, "hwid-d-"+suffix
	if _, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status) VALUES($1,$2,'HWID Test','player','active')`, userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	if _, err := a.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,public_key,key_fingerprint) VALUES($1,$2,'HWID Test Device','test-key',$3)`, deviceID, userID, fmt.Sprintf("%064x", time.Now().UnixNano())); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	x, y, z := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	if _, err := a.ObserveHWID0299(ctx, userID, deviceID, x, now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ObserveHWID0299(ctx, userID, deviceID, y, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	old, err := a.ObserveHWID0299(ctx, userID, deviceID, x, now.Add(2*time.Second))
	if err != nil || old.State != "changed" || old.Pending != y {
		t.Fatalf("baseline replay succeeded: %#v %v", old, err)
	}
	appeal := HWIDAppeal0299{ID: "hwid-appeal-" + suffix, UserID: userID, DeviceID: deviceID, Reason: "Hardware replaced", CreatedAt: now.Add(3 * time.Second)}
	if err := a.SubmitHWIDAppeal0299(ctx, appeal); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ObserveHWID0299(ctx, userID, deviceID, z, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResolveHWIDAppeal0299(ctx, appeal.ID, "admin", "approved", now.Add(5*time.Second)); err != ErrConflict {
		t.Fatalf("stale appeal accepted: %v", err)
	}
	if _, err := a.ConfirmHWID0299(ctx, userID, deviceID, y, now.Add(5*time.Second)); err != ErrNotFound {
		t.Fatalf("CAS stale confirmation accepted: %v", err)
	}
	if _, err := b.ConfirmHWID0299(ctx, userID, deviceID, z, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := a.GetHWID0299(ctx, userID, deviceID, now.Add(7*time.Second))
	if err != nil || got.State != "recognized" || got.Baseline != z {
		t.Fatalf("cross-replica owner confirm: %#v %v", got, err)
	}
}

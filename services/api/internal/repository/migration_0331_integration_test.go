//go:build !launcher_nopgx

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// Uses disposable PostgreSQL, with two independent connections to exercise
// real atomic fencing, checkpoints, resume, and idempotent creation.
func TestMigrationDurability0331(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable NEVERLAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	project := "migration-test-" + suffix
	if _, err := a.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$2)`, project, project); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = a.db.ExecContext(context.Background(), `DELETE FROM migration_events_0331 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = a.db.ExecContext(context.Background(), `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = a.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, err := a.CreateMigration0331(ctx, project, "gravit", "stable-key-for-retry")
	if err != nil {
		t.Fatal(err)
	}
	same, err := b.CreateMigration0331(ctx, project, "gravit", "stable-key-for-retry")
	if err != nil || same.ID != run.ID {
		t.Fatalf("idempotency broken: %+v %v", same, err)
	}
	if _, err := a.ClaimMigration0331(ctx, run.ID, "worker-one", 1200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ClaimMigration0331(ctx, run.ID, "worker-two", time.Second); !errors.Is(err, mw.ErrBusy) {
		t.Fatalf("double claim permitted: %v", err)
	}
	time.Sleep(1400 * time.Millisecond)
	second, err := b.ClaimMigration0331(ctx, run.ID, "worker-two", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	old := mw.Lease{Run: run, Owner: "worker-one", Fence: 1}
	if _, err := a.CheckpointMigration0331(ctx, old, "target_check", json.RawMessage(`{"ok":true}`)); !errors.Is(err, mw.ErrConflict) {
		t.Fatalf("stale fencing accepted: %v", err)
	}
	step1, err := b.CheckpointMigration0331(ctx, second, "target_check", json.RawMessage(`{"ok":true}`))
	if err != nil || step1.Step != "target_inventory" || step1.Revision != 1 {
		t.Fatalf("checkpoint 1: %+v %v", step1, err)
	}
	afterRestart, err := a.GetMigration0331(ctx, run.ID)
	if err != nil || afterRestart.Step != "target_inventory" {
		t.Fatalf("restart state: %+v %v", afterRestart, err)
	}
	if _, err := a.PauseMigration0331(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ClaimMigration0331(ctx, run.ID, "worker-three", time.Second); !errors.Is(err, mw.ErrBusy) {
		t.Fatalf("paused claimed: %v", err)
	}
	if _, err := b.ResumeMigration0331(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	lease, err := a.ClaimMigration0331(ctx, run.ID, "worker-four", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	final, err := a.CheckpointMigration0331(ctx, lease, "target_inventory", json.RawMessage(`{"count":0}`))
	if err != nil || final.Status != "prepared" || final.Revision != 4 {
		t.Fatalf("final step: %+v %v", final, err)
	}
	if _, err := b.ClaimMigration0331(ctx, run.ID, "worker-five", time.Second); !errors.Is(err, mw.ErrBusy) {
		t.Fatalf("prepared claimed: %v", err)
	}
	events, err := b.MigrationEvents0331(ctx, run.ID, 0, 100)
	if err != nil || len(events) != 5 {
		t.Fatalf("expected 5 journal events (created,checkpoint,pause,resume,checkpoint), got %+v %v", events, err)
	}
	for i := 1; i < len(events); i++ {
		if events[i].Sequence <= events[i-1].Sequence {
			t.Fatalf("nonmonotonic journal: %+v", events)
		}
	}
}

func TestMigrationFailureResume0331(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer db.db.Close()
	if _, err := db.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("migration-fail-%d", time.Now().UnixNano())
	if _, err := db.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$2)`, project, project); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.db.ExecContext(context.Background(), `DELETE FROM migration_events_0331 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = db.db.ExecContext(context.Background(), `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = db.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, err := db.CreateMigration0331(ctx, project, "gravit", "failure-test-key")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := db.ClaimMigration0331(ctx, run.ID, "worker-fail", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := db.FailMigration0331(ctx, lease, "transient metadata error")
	if err != nil || failed.Status != "failed" {
		t.Fatalf("failure not persisted: %+v %v", failed, err)
	}
	resumed, err := db.ResumeMigration0331(ctx, run.ID)
	if err != nil || resumed.Step != "target_check" {
		t.Fatalf("resume: %+v %v", resumed, err)
	}
}

//go:build !neverlauncher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	gd "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitdetector"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

func TestGravitAssessmentTransactional0332(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("gravit0332-test-%d", time.Now().UnixNano())
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$2)`, project, project); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_compatibility_0332 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_events_0331 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, err := repo.CreateMigration0331(ctx, project, "gravit", "compat-retry-request-key")
	if err != nil {
		t.Fatal(err)
	}
	report := gd.Report{Format: "neverlauncher.gravit-compatibility.v1", SourceSHA256: fmt.Sprintf("%064x", 77), ClaimedVersion: "5.7.12", Status: "manual", VersionStatus: "unverified", CutoverAllowed: false}
	if _, err = repo.SaveMigrationCompatibility0332(ctx, run.ID, report); !errors.Is(err, mw.ErrBusy) {
		t.Fatalf("assessment before baseline accepted: %v", err)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "worker", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"tested":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	if saved, err := repo.SaveMigrationCompatibility0332(ctx, run.ID, report); err != nil || saved.SourceSHA256 != report.SourceSHA256 {
		t.Fatalf("persist assessment %+v %v", saved, err)
	}
	one, err := repo.GetMigration0331(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.SaveMigrationCompatibility0332(ctx, run.ID, report); err != nil {
		t.Fatal(err)
	}
	two, err := repo.GetMigration0331(ctx, run.ID)
	if err != nil || one.Revision != two.Revision {
		t.Fatalf("idempotency failed %+v %+v %v", one, two, err)
	}
	differentClaim := report
	differentClaim.ClaimedVersion = "5.7.11"
	if _, err = repo.SaveMigrationCompatibility0332(ctx, run.ID, differentClaim); !errors.Is(err, mw.ErrConflict) {
		t.Fatalf("version claim changed silently: %v", err)
	}
	other := report
	other.SourceSHA256 = fmt.Sprintf("%064x", 88)
	if _, err = repo.SaveMigrationCompatibility0332(ctx, run.ID, other); err != nil {
		t.Fatal(err)
	}
	three, err := repo.GetMigration0331(ctx, run.ID)
	if err != nil || three.Revision != two.Revision+1 {
		t.Fatalf("revision not incremented %+v %v", three, err)
	}
	got, err := repo.GetMigrationCompatibility0332(ctx, run.ID)
	if err != nil || got.SourceSHA256 != other.SourceSHA256 {
		t.Fatalf("stored report incorrect %+v %v", got, err)
	}
	events, err := repo.MigrationEvents0331(ctx, run.ID, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Kind == "gravit_compatibility_assessed" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 events for 3 attempts, got %d", count)
	}
}

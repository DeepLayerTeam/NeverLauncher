//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func TestMigrationReportPostgres03313(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, e := r.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := "mig03313-test-" + time.Now().UTC().Format("20060102150405.000000000")
	if _, e := r.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	var runID string
	defer func() {
		for _, q := range []string{`DELETE FROM migration_events_0331 WHERE run_id=$1`, `DELETE FROM migration_runs_0331 WHERE id=$1`} {
			if _, e := r.db.ExecContext(context.Background(), q, runID); e != nil {
				t.Log("cleanup:", e)
			}
		}
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := r.CreateMigration0331(ctx, project, "gravit", "rc-test-idempotency")
	if e != nil {
		t.Fatal(e)
	}
	runID = run.ID
	first, e := r.BuildMigrationReport03313(ctx, run.ID)
	if e != nil {
		t.Fatal(e)
	}
	second, e := r.BuildMigrationReport03313(ctx, run.ID)
	if e != nil {
		t.Fatal(e)
	}
	if first.ReportSHA256 != second.ReportSHA256 || first.Status != "blocked" || len(first.Blockers) < 8 {
		t.Fatalf("missing evidence not blocked: %+v", first)
	}
	if strings.Contains(string(first.ReportSHA256), "password") {
		t.Fatal("secret in hash")
	}
	if _, e = r.ReviewMigrationReport03313(ctx, run.ID, first.ReportSHA256, "tester", "test://proof", strings.Repeat("a", 64)); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("premature review accepted: %v", e)
	}
	if _, e = r.GetReviewedMigrationReport03313(ctx, run.ID); !errors.Is(e, mw.ErrNotFound) {
		t.Fatalf("missing receipt was not missing: %v", e)
	}
	// SQL immutability is checked even against a privileged update in the same
	// transaction; no test fixture survives a rollback.
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_reports_03313(run_id,report_sha256,report,reviewed_by,evidence_sha256,evidence_reference) VALUES($1,$2,'{}'::jsonb,'tester',$2,'ci://test-evidence')`, run.ID, strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `UPDATE migration_reports_03313 SET reviewed_by='forged' WHERE run_id=$1`, run.ID); e == nil {
		t.Fatal("immutable report could be edited")
	}
}

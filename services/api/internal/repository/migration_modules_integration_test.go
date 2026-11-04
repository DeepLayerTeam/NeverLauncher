//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func TestMigrationModuleReportImmutable0338(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, e := r.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := fmt.Sprintf("migration-modules-0338-%d", time.Now().UnixNano())
	if _, e := r.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cleanup := context.Background()
		for _, table := range []string{"migration_wrapper_enrollments_0338", "migration_modules_0338", "migration_source_inventory_0333", "migration_events_0331"} {
			_, _ = r.db.ExecContext(cleanup, `DELETE FROM `+table+` WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		}
		_, _ = r.db.ExecContext(cleanup, `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = r.db.ExecContext(cleanup, `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := r.CreateMigration0331(ctx, project, "gravit", "review-modules-key-0338")
	if e != nil {
		t.Fatal(e)
	}
	report := gm.Report{Format: gm.Format, SourceSHA256: "", InventorySHA256: "", Modules: []gm.Module{}, Wrappers: []gm.Wrapper{}, Blockers: []string{}, Ready: true}
	if _, e := r.SaveMigrationModules0338(ctx, run.ID, report); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("unbound report accepted: %v", e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := r.ClaimMigration0331(ctx, run.ID, "module-test", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = r.CheckpointMigration0331(ctx, lease, step, []byte(`{"verified":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	inventory := inventoryFixture0333(t, "module-source")
	if _, e = r.SaveMigrationInventory0333(ctx, run.ID, inventory); e != nil {
		t.Fatal(e)
	}
	report.SourceSHA256 = inventory.SourceSHA256
	report.InventorySHA256 = inventory.ManifestSHA256
	if _, e = r.SaveMigrationModules0338(ctx, run.ID, report); e != nil {
		t.Fatal(e)
	}
	before, e := r.GetMigration0331(ctx, run.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.SaveMigrationModules0338(ctx, run.ID, report); e != nil {
		t.Fatal(e)
	}
	after, e := r.GetMigration0331(ctx, run.ID)
	if e != nil || before.Revision != after.Revision {
		t.Fatalf("replay changed revision: %v", e)
	}
	report.Blockers = []string{"unknown auth module"}
	report.Ready = false
	if _, e = r.SaveMigrationModules0338(ctx, run.ID, report); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed assessment accepted: %v", e)
	}
	if e = r.RecordMigrationWrapperEnrollment0338(ctx, run.ID, "wrapper.json", "new-node", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); e != nil {
		t.Fatal(e)
	}
	if e = r.RecordMigrationWrapperEnrollment0338(ctx, run.ID, "wrapper.json", "new-node", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); e != nil {
		t.Fatalf("replay failed: %v", e)
	}
	if e = r.RecordMigrationWrapperEnrollment0338(ctx, run.ID, "wrapper.json", "different", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed key accepted: %v", e)
	}
}

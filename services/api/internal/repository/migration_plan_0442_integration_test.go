//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	gp "gitflic.ru/skif4er/launcher/services/api/internal/gravitplan"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func TestMigrationPlanDurableIdempotentAndSourcePinned0442(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, e := repo.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := fmt.Sprintf("gravit0442-%d", time.Now().UnixNano())
	if _, e := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	defer func() {
		background := context.Background()
		for _, table := range []string{"migration_plan_0442", "migration_compatibility_0332", "migration_source_inventory_0333", "migration_events_0331"} {
			_, _ = repo.db.ExecContext(background, `DELETE FROM `+table+` WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		}
		_, _ = repo.db.ExecContext(background, `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := repo.CreateMigration0331(ctx, project, "gravit", "plan-idempotency-key-0442")
	if e != nil {
		t.Fatal(e)
	}
	source := inventoryFixture0333(t, "known verified bytes")
	p := gp.Plan{Format: gp.Format, RunID: run.ID, ProjectID: project, SourceSHA256: source.SourceSHA256, InventorySHA256: source.ManifestSHA256, TargetSHA256: strings.Repeat("a", 64), Status: "manual"}
	p.PlanSHA256, e = gp.Digest(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationPlan0442(ctx, p); !errors.Is(e, mw.ErrBusy) {
		t.Fatalf("early plan saved: %v", e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, err := repo.ClaimMigration0331(ctx, run.ID, "plan-worker", 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"verified":true}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, source); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationPlan0442(ctx, p); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("plan without compatibility accepted: %v", e)
	}
	if _, e = repo.SaveMigrationCompatibility0332(ctx, run.ID, gd.Report{Format: "launcher.gravit-compatibility.v1", SourceSHA256: source.SourceSHA256, Status: "manual", VersionStatus: "unverified"}); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationPlan0442(ctx, p); e != nil {
		t.Fatal(e)
	}
	before, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationPlan0442(ctx, p); e != nil {
		t.Fatal(e)
	}
	after, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil || after.Revision != before.Revision {
		t.Fatalf("idempotent replay changed revision: %v %+v %+v", e, before, after)
	}
	changed := p
	changed.TargetSHA256 = strings.Repeat("b", 64)
	changed.PlanSHA256, e = gp.Digest(changed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationPlan0442(ctx, changed); e != nil {
		t.Fatal(e)
	}
	saved, e := repo.GetMigrationPlan0442(ctx, run.ID)
	if e != nil || saved.PlanSHA256 != changed.PlanSHA256 {
		t.Fatalf("updated plan unavailable: %v", e)
	}
	forged := changed
	forged.SourceSHA256 = strings.Repeat("c", 64)
	forged.PlanSHA256, e = gp.Digest(forged)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationPlan0442(ctx, forged); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("source repin accepted: %v", e)
	}
}

//go:build !launcher_nopgx

package repository

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func TestMigrationContentAtomicReplay0337(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, e := repo.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := fmt.Sprintf("gravit-content-%d", time.Now().UnixNano())
	if _, e := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	defer func() {
		background := context.Background()
		_, _ = repo.db.ExecContext(background, `DELETE FROM migration_content_0337 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM build_workspaces_0226 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM profile_revisions_0221 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM profiles WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM migration_source_inventory_0333 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM migration_events_0331 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(background, `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := repo.CreateMigration0331(ctx, project, "gravit", "content-migration-key-0337")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "content-test", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"verified":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	const profile = `{"title":"Demo","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"classLoaderConfig":"SYSTEM_ARGS","classPath":["minecraft.jar"],"update":["minecraft.jar"],"limited":false}`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, value := range map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "verified-bytecode"} {
		w, e := zw.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(value)); e != nil {
			t.Fatal(e)
		}
	}
	if e = zw.Close(); e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(buf.Bytes())
	inventory, e := inv.Inspect(ctx, bytes.NewReader(buf.Bytes()), int64(buf.Len()), hex.EncodeToString(digest[:]))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, inventory); e != nil {
		t.Fatal(e)
	}
	plan, e := gc.Prepare(ctx, bytes.NewReader(buf.Bytes()), int64(buf.Len()), inventory, "profiles/demo.json", project, "imported-demo", "", "vanilla")
	if e != nil || !plan.Ready {
		t.Fatalf("fixture must be supported: %v %+v", e, plan.Blockers)
	}
	first, e := repo.EnsureMigrationContent0337(ctx, run.ID, "migration-owner", "stable", "migrated-1", plan)
	if e != nil {
		t.Fatal(e)
	}
	second, e := repo.EnsureMigrationContent0337(ctx, run.ID, "migration-owner", "stable", "migrated-1", plan)
	if e != nil || second.ID != first.ID || second.Revision != first.Revision {
		t.Fatalf("idempotent replay failed: %v", e)
	}
	persisted, workspace, e := repo.GetMigrationContent0337(ctx, run.ID, "profiles/demo.json")
	if e != nil || workspace.ID != first.ID || persisted.FilesSHA256 != plan.FilesSHA256 {
		t.Fatalf("receipt not durable: %v", e)
	}
	changed := plan
	changed.FilesSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, e = repo.EnsureMigrationContent0337(ctx, run.ID, "migration-owner", "stable", "migrated-1", changed); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed source replay accepted: %v", e)
	}
	if _, e = repo.EnsureMigrationContent0337(ctx, run.ID, "other-owner", "stable", "migrated-1", plan); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("owner hijack accepted: %v", e)
	}
}

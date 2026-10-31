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

	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func inventoryFixture0333(t *testing.T, content string) inv.Inventory {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, e := z.Create("assets/snapshot.dat")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte(content))
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b.Bytes())
	r, e := inv.Inspect(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()), hex.EncodeToString(h[:]))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestMigrationInventoryTransactional0333(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, e := repo.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := fmt.Sprintf("gravit0333-%d", time.Now().UnixNano())
	if _, e := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_source_inventory_0333 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_compatibility_0332 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_events_0331 WHERE run_id IN (SELECT id FROM migration_runs_0331 WHERE project_id=$1)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := repo.CreateMigration0331(ctx, project, "gravit", "inventory-retry-key-0333")
	if e != nil {
		t.Fatal(e)
	}
	first := inventoryFixture0333(t, "first")
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, first); !errors.Is(e, mw.ErrBusy) {
		t.Fatalf("premature inventory accepted: %v", e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "test-worker", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"verified":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, first); e != nil {
		t.Fatal(e)
	}
	original, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, first); e != nil {
		t.Fatal(e)
	}
	replay, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil || replay.Revision != original.Revision {
		t.Fatalf("duplicate event on replay %v %+v %+v", e, replay, original)
	}
	changed := inventoryFixture0333(t, "second")
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, changed); e != nil {
		t.Fatal(e)
	}
	current, e := repo.GetMigrationInventory0333(ctx, run.ID)
	if e != nil || current.ManifestSHA256 != changed.ManifestSHA256 {
		t.Fatalf("inventory persistence failed %v", e)
	}
	updated, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil || updated.Revision != original.Revision+1 {
		t.Fatalf("revision not incremented %v", e)
	}
	if _, e = repo.SaveMigrationCompatibility0332(ctx, run.ID, gd.Report{Format: "launcher.gravit-compatibility.v1", SourceSHA256: first.SourceSHA256, Status: "manual", VersionStatus: "unverified", CutoverAllowed: false}); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("compat source repin accepted: %v", e)
	}
	if _, e = repo.SaveMigrationCompatibility0332(ctx, run.ID, gd.Report{Format: "launcher.gravit-compatibility.v1", SourceSHA256: changed.SourceSHA256, Status: "manual", VersionStatus: "unverified", CutoverAllowed: false}); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, first); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("inventory source repin accepted: %v", e)
	}
	events, e := repo.MigrationEvents0331(ctx, run.ID, 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, event := range events {
		if event.Kind == "gravit_source_inventoried" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected two inventory commits, got %d", count)
	}
}

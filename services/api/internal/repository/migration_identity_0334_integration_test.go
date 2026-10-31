//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// PostgreSQL integration covers actual row locks, stable snapshot replay,
// target identity collision detection and re-verification across transactions.
func TestMigrationIdentityTransactional0334(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL 17")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, e := repo.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	project := "identity334-" + suffix
	user := "identity-user-" + suffix
	if _, e := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	defer func() {
		idQuery := `SELECT id FROM migration_runs_0331 WHERE project_id=$1`
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_identity_rows_0334 WHERE run_id IN (`+idQuery+`)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_identity_snapshots_0334 WHERE run_id IN (`+idQuery+`)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_source_inventory_0333 WHERE run_id IN (`+idQuery+`)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_compatibility_0332 WHERE run_id IN (`+idQuery+`)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_events_0331 WHERE run_id IN (`+idQuery+`)`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM minecraft_profiles WHERE user_id=$1`, user)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, user)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := repo.CreateMigration0331(ctx, project, "gravit", "identity-stable-0334")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "identity-test-worker", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	source := inventoryFixture0333(t, "identity334-snapshot")
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, source); e != nil {
		t.Fatal(e)
	}
	uuid := "11111111-2222-4333-8444-555555555555"
	records := []gi.Account{{Provider: "fileauth", SourceID: uuid, Username: "Alice334", UUID: uuid, SourcePath: "modules-config/FileAuthSystem/Database.json"}}
	first, e := repo.SaveMigrationIdentities0334(ctx, run.ID, source.SourceSHA256, source.ManifestSHA256, records)
	if e != nil || first.Summary["pending_import"] != 1 || first.Ready {
		t.Fatalf("first: %+v %v", first, e)
	}
	r1, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil {
		t.Fatal(e)
	}
	again, e := repo.SaveMigrationIdentities0334(ctx, run.ID, source.SourceSHA256, source.ManifestSHA256, records)
	if e != nil || again.Summary["pending_import"] != 1 {
		t.Fatalf("replay %+v %v", again, e)
	}
	r2, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil || r1.Revision != r2.Revision {
		t.Fatalf("replay revision %d -> %d: %v", r1.Revision, r2.Revision, e)
	}
	if _, e = repo.SaveMigrationIdentities0334(ctx, run.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{{Provider: "fileauth", SourceID: uuid, Username: "SomeoneElse", UUID: uuid, SourcePath: records[0].SourcePath}}); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed source map accepted: %v", e)
	}
	if _, e = repo.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'Alice334')`, user, user+"@example.invalid"); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.db.ExecContext(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name,issuer,realm,subject,identity_version) VALUES($1,$2,'Alice334','launcher','local',$2,'legacy-fileauth-v1')`, user, uuid); e != nil {
		t.Fatal(e)
	}
	verified, e := repo.VerifyMigrationIdentities0334(ctx, run.ID)
	if e != nil || verified.Summary["matched"] != 1 || verified.Rows[0].TargetUserID != user || !verified.Ready {
		t.Fatalf("verify %+v %v", verified, e)
	}
	persisted, e := repo.GetMigrationIdentities0334(ctx, run.ID)
	if e != nil || persisted.Rows[0].UUID != uuid || persisted.Summary["matched"] != 1 {
		t.Fatalf("persist %+v %v", persisted, e)
	}
	latest, e := repo.GetMigration0331(ctx, run.ID)
	if e != nil || latest.Revision != r2.Revision+1 {
		t.Fatalf("verification event revision: %+v %v", latest, e)
	}
	// Existing name with a foreign UUID must block, never merge by nickname.
	second := []gi.Account{{Provider: "sql", SourceID: "id-2", Username: "Alice334", UUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", SourcePath: "sql-export/users.csv"}}
	run2, e := repo.CreateMigration0331(ctx, project, "gravit", "second-identity-key-0334")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run2.ID, "worker", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run2.ID, source); e != nil {
		t.Fatal(e)
	}
	blocked, e := repo.SaveMigrationIdentities0334(ctx, run2.ID, source.SourceSHA256, source.ManifestSHA256, second)
	if e != nil || blocked.Summary["blocked"] != 1 || blocked.Ready {
		t.Fatalf("UUID collision accepted %+v %v", blocked, e)
	}
}

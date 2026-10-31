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

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcredentials"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// Requires a disposable PostgreSQL. Exercises actual inserts, transaction
// rollback, receipt replay, UUID ownership, and CAS-upgraded password replay.
func TestMigrationAuthAtomicIdempotent0335(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
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
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	project := "auth335-" + suffix
	if _, e := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	var userID string
	defer func() {
		c := context.Background()
		idQuery := `SELECT id FROM migration_runs_0331 WHERE project_id=$1`
		for _, table := range []string{"migration_auth_imports_0335", "migration_identity_rows_0334", "migration_identity_snapshots_0334", "migration_source_inventory_0333", "migration_compatibility_0332", "migration_events_0331"} {
			_, _ = repo.db.ExecContext(c, `DELETE FROM `+table+` WHERE run_id IN (`+idQuery+`)`, project)
		}
		_, _ = repo.db.ExecContext(c, `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		if userID != "" {
			_, _ = repo.db.ExecContext(c, `DELETE FROM users WHERE id=$1`, userID)
		}
		_, _ = repo.db.ExecContext(c, `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := repo.CreateMigration0331(ctx, project, "gravit", "auth-migration-0335-key")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "worker-0335", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	source := inventoryFixture0333(t, "auth335-source")
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, source); e != nil {
		t.Fatal(e)
	}
	account := gi.Account{Provider: "sql", SourceID: "db-id-" + suffix, Username: "Auth335", UUID: "11111111-2222-4333-8444-555555555555", SourcePath: "sql-export/users.csv"}
	mapped, e := repo.SaveMigrationIdentities0334(ctx, run.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{account})
	if e != nil || mapped.Summary["pending_import"] != 1 {
		t.Fatalf("map: %+v %v", mapped, e)
	}
	encoded, e := fileauth.EncodeCredential("sha256-hex", strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	c := gc.Credential{Account: account, PasswordHash: encoded, Algorithm: "sha256-hex", State: "importable"}
	input := []gc.Credential{c}
	dry, e := repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", input, true)
	if e != nil || !dry.DryRun || dry.Imported != 1 {
		t.Fatalf("dry-run: %+v %v", dry, e)
	}
	userID = migratedUserID0335(account)
	var count int
	if e = repo.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id=$1`, userID).Scan(&count); e != nil || count != 0 {
		t.Fatal("dry-run created users", e)
	}
	// A bad hash selection is rejected by server-side source parser; once a
	// decision has been imported, a different format cannot replay the receipt.
	saved, e := repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", input, false)
	if e != nil || saved.Imported != 1 || saved.DryRun {
		t.Fatalf("import: %+v %v", saved, e)
	}
	var hash, uuid, role string
	e = repo.db.QueryRowContext(ctx, `SELECT u.password_hash,m.uuid,u.role_id FROM users u JOIN minecraft_profiles m ON m.user_id=u.id WHERE u.id=$1`, userID).Scan(&hash, &uuid, &role)
	if e != nil || hash != encoded || uuid != account.UUID || role != "player" {
		t.Fatalf("incorrect account/UUID: %q %q %q %v", hash, uuid, role, e)
	}
	if _, e = repo.db.ExecContext(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, userID, "$argon2id$verified-upgrade"); e != nil {
		t.Fatal(e)
	}
	replay, e := repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", input, false)
	if e != nil || replay.Imported != 1 {
		t.Fatalf("replay: %+v %v", replay, e)
	}
	if _, e = repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "bcrypt", input, false); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed decision replayed: %v", e)
	}
	if e = repo.db.QueryRowContext(ctx, `SELECT count(*) FROM migration_events_0331 WHERE run_id=$1 AND kind='gravit_auth_imported'`, run.ID).Scan(&count); e != nil || count != 1 {
		t.Fatalf("expected exactly one event %d %v", count, e)
	}

	// A separate migration run can map this account by its exact UUID, but
	// must not replace the Never credential, even if a different source hash
	// is explicitly offered by an operator.
	run2, e := repo.CreateMigration0331(ctx, project, "gravit", "auth-second-run-0335-key")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run2.ID, "worker-2", 10*time.Second)
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
	matched, e := repo.SaveMigrationIdentities0334(ctx, run2.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{account})
	if e != nil || matched.Summary["matched"] != 1 {
		t.Fatalf("expected UUID match: %+v %v", matched, e)
	}
	replacement := c
	replacement.PasswordHash = strings.Repeat("c", 64)
	preserved, e := repo.ImportMigrationCredentials0335(ctx, run2.ID, source.SourceSHA256, "", []gc.Credential{replacement}, false)
	if e != nil || preserved.ExistingUnchanged != 1 || preserved.Imported != 0 || preserved.Complete {
		t.Fatalf("matched account overwritten: %+v %v", preserved, e)
	}
	if e = repo.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&hash); e != nil || hash != "$argon2id$verified-upgrade" {
		t.Fatalf("source password overwrote Never: %v %q", e, hash)
	}
}

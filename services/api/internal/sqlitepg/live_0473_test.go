package sqlitepg

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestLiveMapping0473(t *testing.T) {
	if _, err := PopulateLive0473(context.Background(), ""); err == nil {
		t.Fatal("accepted empty DSN")
	}
	if _, err := bool0473(int64(2)); err == nil {
		t.Fatal("accepted invalid boolean")
	}
	if b, err := bool0473(int64(0)); err != nil || b != false {
		t.Fatalf("bool: %v %v", b, err)
	}
	if _, err := json0473(`{broken`); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	if _, err := instant0473(int64(-1), false); err == nil {
		t.Fatal("accepted negative timestamp")
	}
	if v, err := instant0473(int64(0), true); err != nil || v != nil {
		t.Fatalf("optional zero: %v %v", v, err)
	}
	if v, err := instant0473(int64(1), false); err != nil || !v.(time.Time).Equal(time.Unix(0, 1)) {
		t.Fatalf("nanoseconds: %v %v", v, err)
	}
	for _, r := range rules0473() {
		if r.source == "" || r.target == "" || len(r.columns) == 0 {
			t.Fatalf("incomplete live mapping: %+v", r)
		}
	}
	if err := checkManifest0473(map[string]any{"manifest": "{}", "status": "published"}); err == nil {
		t.Fatal("invalid manifest accepted")
	}
}

// Run ONLY with an isolated, empty PostgreSQL test database owned by CI.
// The integration test applies actual embedded migrations and reads through
// SQLRepository, not staging tables or a mock database.
func TestLiveSQLiteToSQLRepository0473(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_PG_LIVE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated LAUNCHER_PG_LIVE_TEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var empty bool
	err = pg.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, Schema).Scan(&empty)
	_ = pg.Close(ctx)
	if err != nil || !empty {
		t.Fatalf("must be a dedicated, untouched PostgreSQL test database: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = dbmigrate.Apply(ctx, db); err != nil {
		t.Fatalf("apply real PostgreSQL schema: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "core.db")
	backup := filepath.Join(dir, "core-backup.db")
	core, err := sqlitecore.Open(ctx, sqlitedurable.Options{Path: src})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SaveProject(ctx, model.Project{ID: "project-47", Name: "Imported Project"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SaveProfile(ctx, model.Profile{ID: "vanilla-1", ProjectID: "project-47", Name: "Vanilla 1", Loader: "vanilla", MinecraftVersion: "1.21.1", JavaMajor: 21}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SaveUser(ctx, model.User{ID: "u1", Email: "owner@example.test", DisplayName: "Owner", RoleID: "owner", Status: "active", PasswordHash: "persisted-password-hash"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	draft, err := core.CreateDraft(ctx, "project-47", "vanilla-1", "stable", "1.0.0", "test")
	if err != nil {
		t.Fatal(err)
	}
	draft.Manifest.Files = []model.ManifestFile{{Path: "mods/example.jar", Size: 128, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", URL: "https://example.test/files/example.jar", Required: true, Ownership: "required", Mirrors: []string{"https://mirror.example.test/example.jar"}}}
	if _, err = core.UpdateDraftManifest(ctx, "project-47", draft.ID, draft.Manifest, "test"); err != nil {
		t.Fatal(err)
	}
	if err = core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = sqlitedurable.OnlineBackup(ctx, src, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = Import(ctx, backup, dsn); err != nil {
		t.Fatalf("staging: %v", err)
	}
	live, err := PopulateLive0473(ctx, dsn)
	if err != nil {
		t.Fatalf("LIVE conversion: %v", err)
	}
	if !live.Verified || live.ReadyForBackendCutover || live.Files != 1 || live.LocalIdentities != 1 || len(live.LiveTables) != len(rules0473()) {
		t.Fatalf("incorrect live receipt: %+v", live)
	}
	api := repository.NewPostgresRepository(dsn, "")
	project, err := api.GetProject("project-47")
	if err != nil || project.Name != "Imported Project" {
		t.Fatalf("SQLRepository project: %+v %v", project, err)
	}
	profiles, err := api.ListProfiles("project-47")
	if err != nil || len(profiles) != 1 || profiles[0].MinecraftVersion != "1.21.1" || profiles[0].JavaMajor != 21 {
		t.Fatalf("SQLRepository profiles: %+v %v", profiles, err)
	}
	versions, err := api.ListVersions("project-47")
	if err != nil || len(versions) != 1 || versions[0].Manifest.ProfileSnapshot == nil {
		t.Fatalf("SQLRepository versions: %+v %v", versions, err)
	}
	u, err := api.GetUserByEmail("owner@example.test")
	if err != nil || u.ID != "u1" || u.PasswordHash != "persisted-password-hash" {
		t.Fatalf("SQLRepository user: %+v %v", u, err)
	}
	pg2, er := pgx.Connect(ctx, dsn)
	if er != nil {
		t.Fatal(er)
	}
	var identityUser string
	er = pg2.QueryRow(ctx, `SELECT user_id FROM auth_identities WHERE provider='local' AND subject='u1'`).Scan(&identityUser)
	pg2.Close(ctx)
	if er != nil || identityUser != "u1" {
		t.Fatalf("SQLRepository local login identity: %s %v", identityUser, er)
	}
	if _, err = PopulateLive0473(ctx, dsn); err == nil {
		t.Fatal("reimport over live database accepted")
	}
	files, err := api.ListFiles("project-47", versions[0].ID)
	if err != nil || len(files) != 1 || files[0].Path != "mods/example.jar" || files[0].URL != "https://example.test/files/example.jar" || len(files[0].Mirrors) != 1 || files[0].Mirrors[0] != "https://mirror.example.test/example.jar" {
		t.Fatalf("SQLRepository file links: %+v %v", files, err)
	}
}

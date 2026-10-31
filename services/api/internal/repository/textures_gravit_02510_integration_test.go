package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Requires TEST_PG_DSN_02510 pointing to a disposable PostgreSQL 17+ instance.
// Runs real migrations, Staging, CAS, provenance, replay and owner isolation.
func TestTextureGravitImportPostgres02510(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_02510")
	if dsn == "" {
		t.Skip("TEST_PG_DSN_02510 not provided")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("gravit_02510_%d", time.Now().UnixNano())
	if !regexp.MustCompile(`^gravit_02510_[0-9]+$`).MatchString(schema) {
		t.Fatal("invalid schema")
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE users(id TEXT PRIMARY KEY);
  CREATE TABLE minecraft_profiles(uuid TEXT PRIMARY KEY,user_id TEXT UNIQUE NOT NULL REFERENCES users(id),name TEXT NOT NULL,issuer TEXT NOT NULL DEFAULT 'launcher',realm TEXT NOT NULL DEFAULT 'local',subject TEXT NOT NULL DEFAULT '',identity_version TEXT NOT NULL DEFAULT 'local-v1',created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
  CREATE TABLE server_bridge_textures_v2(player_uuid TEXT PRIMARY KEY,username TEXT NOT NULL,skin_url TEXT NOT NULL,cape_url TEXT NOT NULL,model TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL);
  INSERT INTO users(id) VALUES('alice'),('bob');
  INSERT INTO minecraft_profiles(uuid,user_id,name) VALUES('11111111-2222-4333-8444-555555555555','alice','Alice'),('99999999-aaaa-4bbb-8ccc-dddddddddddd','bob','Bob');`)
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"0067_texture_identity_0251.sql", "0068_texture_upload_0252.sql", "0069_texture_storage_0253.sql", "0070_texture_fetch_0254.sql", "0071_texture_service_0255.sql", "0072_texture_admin_0259.sql", "0073_texture_gravit_import_02510.sql"} {
		b, e := os.ReadFile("../dbmigrate/sql/" + filename)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(b)); e != nil {
			t.Fatalf("apply %s: %v", filename, e)
		}
	}
	r := &SQLRepository{db: db}
	p := model.MinecraftProfile{UUID: "11111111-2222-4333-8444-555555555555", UserID: "alice", Name: "Alice", Issuer: "launcher", Realm: "local"}
	sum := sha256.Sum256([]byte("normalized test PNG bytes"))
	digest := hex.EncodeToString(sum[:])
	input := VerifiedTexture0252{Digest: digest, Size: 512, Width: 64, Height: 64, Driver: "local", ObjectKey: "texture-blobs/sha256/" + digest[:2] + "/" + digest + ".png", Kind: "skin", Model: "slim", Visibility: "public", Source: "managed-gravit-import", ExpectedRevision: 0, GravitSourceID: "gravit-prod", GravitRowID: "upstream-row", GravitExternalUUID: "11111111-2222-4333-8444-555555555555", GravitOriginalHash: digest}
	already, rev, exists, e := r.GravitImportState02510(ctx, input.GravitSourceID, input.GravitRowID, p, "skin")
	if e != nil || already || exists || rev != 0 {
		t.Fatalf("preflight %v %v %v %v", already, rev, exists, e)
	}
	if e = r.StageTextureUpload0253(ctx, p, input); e != nil {
		t.Fatal(e)
	}
	assignment, e := r.UploadTexture0252(ctx, p, input)
	if e != nil || assignment.Revision != 1 || assignment.Source != "imported" {
		t.Fatalf("import %+v %v", assignment, e)
	}
	already, _, _, e = r.GravitImportState02510(ctx, input.GravitSourceID, input.GravitRowID, p, "skin")
	if e != nil || !already {
		t.Fatalf("receipt missing: %v", e)
	}
	if _, e = r.UploadTexture0252(ctx, p, input); !errors.Is(e, ErrGravitAlreadyImported02510) {
		t.Fatalf("reimport mutation allowed: %v", e)
	}
	var count int
	e = db.QueryRowContext(ctx, `SELECT count(*) FROM texture_assignment_revisions WHERE event='gravit-import' AND actor_user_id LIKE 'system:%'`).Scan(&count)
	if e != nil || count != 1 {
		t.Fatalf("audit actor not system, count=%d err=%v", count, e)
	}
	foreign := p
	foreign.UserID = "bob"
	if _, e = r.UploadTexture0252(ctx, foreign, input); !errors.Is(e, ErrNotFound) {
		t.Fatalf("foreign UUID accepted: %v", e)
	}
}

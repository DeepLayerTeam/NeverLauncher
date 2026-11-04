package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Run with TEST_PG_DSN_0259 set to an isolated PostgreSQL 17+ instance.
// This exercises the real migrations, row locking, CAS, default-delivery,
// per-user deny/allow precedence, privacy and immutable audit rows.
func TestTextureAdminEndToEndPostgres0259(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_0259")
	if dsn == "" {
		t.Skip("TEST_PG_DSN_0259 not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("textures_0259_%d", time.Now().UnixNano())
	if !regexp.MustCompile(`^textures_0259_[0-9]+$`).MatchString(schema) {
		t.Fatal("unsafe schema")
	}
	if _, err = db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	if _, err = db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	setup := `CREATE TABLE users(id TEXT PRIMARY KEY);
  CREATE TABLE projects(id TEXT PRIMARY KEY);
  CREATE TABLE minecraft_profiles(uuid TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL);
  CREATE TABLE server_bridge_textures_v2(player_uuid TEXT PRIMARY KEY,username TEXT NOT NULL,skin_url TEXT NOT NULL,cape_url TEXT NOT NULL,model TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL);
  INSERT INTO users(id) VALUES('admin'),('alice'),('bob');
  INSERT INTO projects(id) VALUES('demo');
  INSERT INTO minecraft_profiles(uuid,user_id,name) VALUES
   ('11111111-2222-4333-8444-555555555555','alice','Alice'),
   ('99999999-aaaa-4bbb-8ccc-dddddddddddd','bob','Bob');`
	if _, err = db.ExecContext(ctx, setup); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"0067_texture_identity_0251.sql", "0068_texture_upload_0252.sql", "0069_texture_storage_0253.sql", "0070_texture_fetch_0254.sql", "0071_texture_service_0255.sql", "0072_texture_admin_0259.sql"} {
		b, e := os.ReadFile("../dbmigrate/sql/" + filename)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(b)); e != nil {
			t.Fatalf("migration %s: %v", filename, e)
		}
	}
	repo := &SQLRepository{db: db, publicURL: "https://textures.example.test"}
	policy, err := repo.GetTexturePolicy0259(ctx, "")
	if err != nil || policy.Revision != 0 || !policy.AllowPlayerSkins || policy.AllowPlayerCapes {
		t.Fatalf("initial policy: %+v %v", policy, err)
	}
	digest := strings.Repeat("a", 64)
	_, err = db.ExecContext(ctx, `INSERT INTO texture_blobs(digest,byte_size,width,height,storage_driver,object_key,status,verified_at)
 VALUES($1,2048,64,64,'local',$2,'verified',now())`, digest, "texture-blobs/sha256/aa/"+digest+".png")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO texture_assignments(realm,profile_uuid,user_id,kind,blob_digest,source,model,visibility)
 VALUES('local-project','11111111-2222-4333-8444-555555555555','alice','skin',$1,'managed-upload','slim','public')`, digest)
	if err != nil {
		t.Fatal(err)
	}
	input := policy
	input.AllowPlayerSkins = false
	input.DefaultSkinDigest = digest
	input.DefaultSkinModel = "slim"
	input.FallbackSkinDigest = digest
	input.FallbackSkinModel = "classic"
	input.MaxBytesPerPlayer = 22000000
	change := TexturePolicyChange0259{ExpectedRevision: 0, Policy: input, Reason: "admin fallback policy"}
	updated, err := repo.SaveTexturePolicy0259(ctx, "", change, "admin")
	if err != nil || updated.Revision != 1 || updated.DefaultSkinModel != "slim" {
		t.Fatalf("save policy: %+v %v", updated, err)
	}
	if _, err = repo.SaveTexturePolicy0259(ctx, "", change, "admin"); !errors.Is(err, ErrTexturePolicyConflict0259) {
		t.Fatalf("stale CAS allowed: %v", err)
	}
	// Admin fallback is returned for both a policy-blocked uploader and a player
	// who uploaded their own skin.
	for _, uuid := range []string{"11111111-2222-4333-8444-555555555555", "99999999-aaaa-4bbb-8ccc-dddddddddddd"} {
		texture, found, e := repo.ReadTextureProfile0251(ctx, uuid)
		expectedModel := "slim"
		if uuid == "11111111-2222-4333-8444-555555555555" {
			expectedModel = "classic"
		}
		if e != nil || !found || texture.SkinURL != "https://textures.example.test/api/v1/textures/blob/"+digest || texture.Model != expectedModel {
			t.Fatalf("fallback %s: %+v %v %v", uuid, texture, found, e)
		}
	}
	var allowed bool
	if err = db.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('','alice','skin')`).Scan(&allowed); err != nil || allowed {
		t.Fatalf("policy should deny Alice: %v %v", allowed, err)
	}
	if err = repo.SetTextureException0259(ctx, "", "alice", TextureException0259{Kind: "skin", Decision: "allow", Reason: "verified user exception"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('','alice','skin')`).Scan(&allowed); err != nil || !allowed {
		t.Fatalf("individual allow failed: %v %v", allowed, err)
	}
	if err = repo.SetTextureException0259(ctx, "", "alice", TextureException0259{Kind: "skin", Decision: "deny", Reason: "revoked user exception"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('','alice','skin')`).Scan(&allowed); err != nil || allowed {
		t.Fatalf("individual deny failed: %v %v", allowed, err)
	}
	if err = repo.SetTextureException0259(ctx, "", "alice", TextureException0259{Kind: "skin", Decision: "inherit", Reason: "return to project rules"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('','alice','skin')`).Scan(&allowed); err != nil || allowed {
		t.Fatalf("inherit failed: %v %v", allowed, err)
	}
	// A legacy cape grant is superseded by an explicit individual deny.
	if _, err = db.ExecContext(ctx, `INSERT INTO texture_cape_grants(project_id,user_id,granted,actor_user_id) VALUES('','alice',true,'admin')`); err != nil {
		t.Fatal(err)
	}
	if err = repo.SetTextureException0259(ctx, "", "alice", TextureException0259{Kind: "cape", Decision: "deny", Reason: "moderation decision"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('','alice','cape')`).Scan(&allowed); err != nil || allowed {
		t.Fatalf("deny must override legacy grant: %v %v", allowed, err)
	}
	history, err := repo.ListTexturePolicyHistory0259(ctx, "")
	if err != nil || len(history) != 1 || history[0].ActorUserID != "admin" {
		t.Fatalf("policy history: %+v %v", history, err)
	}
	exceptions, err := repo.ListTextureExceptionHistory0259(ctx, "")
	if err != nil || len(exceptions) != 4 {
		t.Fatalf("exception history: %+v %v", exceptions, err)
	}
	// A private texture cannot be silently turned into a public default.
	if _, err = db.ExecContext(ctx, `UPDATE texture_assignments SET visibility='private' WHERE profile_uuid='11111111-2222-4333-8444-555555555555'`); err != nil {
		t.Fatal(err)
	}
	input.DefaultCapeDigest = digest
	_, err = repo.SaveTexturePolicy0259(ctx, "", TexturePolicyChange0259{ExpectedRevision: 1, Policy: input, Reason: "invalid private texture"}, "admin")
	if !errors.Is(err, ErrTexturePolicyInvalid0259) {
		t.Fatalf("invalid private default accepted: %v", err)
	}
}

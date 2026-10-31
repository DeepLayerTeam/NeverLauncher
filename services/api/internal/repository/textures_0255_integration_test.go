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

func TestTextureServiceOwnershipAndLifecyclePostgres0255(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_0255")
	if dsn == "" {
		t.Skip("set TEST_PG_DSN_0255 to an isolated PostgreSQL 17+ database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("textures_0255_%d", time.Now().UnixNano())
	if !regexp.MustCompile(`^textures_0255_[0-9]+$`).MatchString(schema) {
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
  CREATE TABLE minecraft_profiles(uuid TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL);
  CREATE TABLE server_bridge_textures_v2(player_uuid TEXT PRIMARY KEY,username TEXT NOT NULL,skin_url TEXT NOT NULL,cape_url TEXT NOT NULL,model TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL);
  INSERT INTO users(id) VALUES('alice'),('bob');
  INSERT INTO minecraft_profiles(uuid,user_id,name) VALUES
    ('11111111-2222-4333-8444-555555555555','alice','Alice'),
    ('99999999-aaaa-4bbb-8ccc-dddddddddddd','bob','Bob');`
	if _, err = db.ExecContext(ctx, setup); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"0067_texture_identity_0251.sql", "0068_texture_upload_0252.sql", "0069_texture_storage_0253.sql", "0070_texture_fetch_0254.sql", "0071_texture_service_0255.sql"} {
		data, e := os.ReadFile("../dbmigrate/sql/" + filename)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(data)); e != nil {
			t.Fatalf("migration %s: %v", filename, e)
		}
	}
	r := &SQLRepository{db: db, publicURL: "https://launcher.example"}
	alice := model.MinecraftProfile{UUID: "11111111-2222-4333-8444-555555555555", UserID: "alice", Name: "Alice", Realm: "local", Issuer: "launcher"}
	bob := model.MinecraftProfile{UUID: "99999999-aaaa-4bbb-8ccc-dddddddddddd", UserID: "bob", Name: "Bob", Realm: "local", Issuer: "launcher"}
	sum := sha256.Sum256([]byte("normalized-mock-texture-bytes"))
	digest := hex.EncodeToString(sum[:])
	input := VerifiedTexture0252{Digest: digest, Size: 30, Width: 64, Height: 64, Driver: "local", ObjectKey: "texture-blobs/sha256/" + digest[:2] + "/" + digest + ".png", Kind: "skin", Model: "classic", Visibility: "public", ExpectedRevision: 0}
	first, err := r.UploadTexture0252(ctx, alice, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || !first.Active {
		t.Fatalf("bad first upload: %+v", first)
	}
	library, err := r.ListSavedTextures0255(ctx, alice, "skin")
	if err != nil || len(library) != 1 || library[0].Digest != digest {
		t.Fatalf("saved item: %+v %v", library, err)
	}
	notOwned, err := r.ListSavedTextures0255(ctx, bob, "skin")
	if err != nil || len(notOwned) != 0 {
		t.Fatalf("cross-user library leak: %+v %v", notOwned, err)
	}
	foreign := alice
	foreign.UserID = "bob"
	if _, err = r.SelectSavedTexture0255(ctx, foreign, "skin", digest, 1, "classic", "public"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UUID spoofing: %v", err)
	}
	if _, err = r.SelectSavedTexture0255(ctx, bob, "skin", digest, 0, "classic", "public"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign digest reuse: %v", err)
	}
	if _, found, err := r.ReadSavedTextureBlob0255(ctx, bob, "skin", digest); err != nil || found {
		t.Fatalf("foreign saved preview: %v %v", found, err)
	}
	if _, found, err := r.ReadSavedTextureBlob0255(ctx, alice, "skin", digest); err != nil || !found {
		t.Fatalf("owned saved preview: %v %v", found, err)
	}
	if err = r.DeleteSavedTexture0255(ctx, alice, "skin", digest); !errors.Is(err, ErrTextureInUse0255) {
		t.Fatalf("active item deletion: %v", err)
	}
	if _, err = r.SelectSavedTexture0255(ctx, alice, "skin", digest, 0, "slim", "public"); !errors.Is(err, ErrTextureRevisionConflict0251) {
		t.Fatalf("missing CAS: %v", err)
	}
	selected, err := r.SelectSavedTexture0255(ctx, alice, "skin", digest, 1, "slim", "private")
	if err != nil || selected.Revision != 2 || selected.Model != "slim" {
		t.Fatalf("select: %+v %v", selected, err)
	}
	if _, err = r.ClearTexture0255(ctx, alice, "skin", 1, false); !errors.Is(err, ErrTextureRevisionConflict0251) {
		t.Fatalf("stale reset: %v", err)
	}
	cleared, err := r.ClearTexture0255(ctx, alice, "skin", 2, false)
	if err != nil || cleared.Revision != 3 || cleared.Active || cleared.BlobDigest != "" || cleared.Visibility != "private" {
		t.Fatalf("reset: %+v %v", cleared, err)
	}
	public, found, err := r.ReadTextureProfile0251(ctx, alice.UUID)
	if err != nil || !found || public.SkinURL != "" {
		t.Fatalf("reset still publicly visible: %+v %v %v", public, found, err)
	}
	if _, err = r.UpdateTextureSelection0251(ctx, alice, "skin", 3, "slim", "public", true); !errors.Is(err, ErrTextureNotSelected0255) {
		t.Fatalf("reactivated tombstone: %v", err)
	}
	// Returning to the saved texture needs no re-upload, but does need the new CAS.
	again, err := r.SelectSavedTexture0255(ctx, alice, "skin", digest, 3, "classic", "public")
	if err != nil || again.Revision != 4 {
		t.Fatalf("reselect: %+v %v", again, err)
	}
	if _, err = r.ClearTexture0255(ctx, alice, "skin", 4, true); err != nil {
		t.Fatalf("delete current: %v", err)
	}
	library, err = r.ListSavedTextures0255(ctx, alice, "skin")
	if err != nil || len(library) != 0 {
		t.Fatalf("deleted item retained: %+v %v", library, err)
	}
	if _, err = r.SelectSavedTexture0255(ctx, alice, "skin", digest, 5, "classic", "public"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted digest reselect: %v", err)
	}
	history, err := r.ListTextureRevisions0251(ctx, alice, "skin")
	if err != nil || len(history) != 5 {
		t.Fatalf("history lost: %d %v", len(history), err)
	}
	if history[0].Event != "delete" || history[1].Event != "select" || history[2].Event != "reset" {
		t.Fatalf("unexpected event order: %+v", history)
	}
	var owners int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM texture_blob_owners WHERE user_id='alice'`).Scan(&owners); err != nil || owners != 0 {
		t.Fatalf("quota not released %d %v", owners, err)
	}
	// Previously cleared assets remain in other users' libraries, not GC victims.
	input.ExpectedRevision = 0
	if _, err = r.UploadTexture0252(ctx, bob, input); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ClearTexture0255(ctx, bob, "skin", 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE texture_blobs SET created_at=now()-interval '10 days',last_upload_at=now()-interval '10 days' WHERE digest=$1`, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE texture_assignment_revisions SET created_at=now()-interval '10 days'`); err != nil {
		t.Fatal(err)
	}
	garbage, err := r.ClaimTextureGarbage0253(ctx, "local", 100)
	if err != nil || len(garbage) != 0 {
		t.Fatalf("saved-but-inactive asset claimed by GC: %+v %v", garbage, err)
	}
	// A cape saved in a library cannot bypass per-user policy.
	if _, err = db.ExecContext(ctx, `INSERT INTO texture_saved_items(user_id,digest,kind,model,source) VALUES('bob',$1,'cape','classic','managed-upload')`, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = r.SelectSavedTexture0255(ctx, bob, "cape", digest, 0, "classic", "public"); !errors.Is(err, ErrTextureCapeDenied0251) {
		t.Fatalf("cape grant bypass: %v", err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO texture_cape_grants(project_id,user_id,granted,actor_user_id) VALUES('', 'bob',true,'alice')`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.SelectSavedTexture0255(ctx, bob, "cape", digest, 0, "classic", "public"); err != nil {
		t.Fatalf("granted cape: %v", err)
	}
}

func TestTextureServiceValidation0255(t *testing.T) {
	for _, s := range []string{"", "A" + "012345678901234567890123456789012345678901234567890123456789012", "../" + "0000000000000000000000000000000000000000000000000000000000000000"} {
		if validTextureDigest0255(s) {
			t.Errorf("accepted invalid digest %q", s)
		}
	}
	if !validTextureDigest0255("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatal("valid sha256 rejected")
	}
	if validTextureKind0255("official") || validTextureKind0255("SKIN") {
		t.Fatal("invalid texture kind accepted")
	}
}

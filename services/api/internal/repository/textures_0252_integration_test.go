package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestSecureTextureUploadPostgres0252(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_0252")
	if dsn == "" {
		t.Skip("TEST_PG_DSN_0252 required for integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("texture_0252_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	if _, err = db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	setup := `CREATE TABLE users(id TEXT PRIMARY KEY);
      CREATE TABLE minecraft_profiles(uuid TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL);
      CREATE TABLE server_bridge_textures_v2(player_uuid TEXT PRIMARY KEY,username TEXT NOT NULL,skin_url TEXT NOT NULL,cape_url TEXT NOT NULL,model TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL);
      INSERT INTO users VALUES('owner'),('other');
      INSERT INTO minecraft_profiles VALUES('11111111-2222-4333-8444-555555555555','owner','Steve'),('99999999-2222-4333-8444-555555555555','other','Other');`
	if _, err = db.ExecContext(ctx, setup); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0067_texture_identity_0251.sql", "0068_texture_upload_0252.sql"} {
		payload, err := os.ReadFile("../dbmigrate/sql/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, string(payload)); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
	r := &SQLRepository{db: db, publicURL: "https://launcher.example"}
	p := model.MinecraftProfile{UUID: "11111111-2222-4333-8444-555555555555", UserID: "owner", Name: "Steve", Realm: "local", Issuer: "neverlauncher"}
	payload := []byte("already-verified-normalized-image")
	sha := sha256.Sum256(payload)
	digest := hex.EncodeToString(sha[:])
	input := VerifiedTexture0252{Digest: digest, Width: 64, Height: 64, Size: int64(len(payload)), Driver: "local", ObjectKey: "texture-blobs/sha256/" + digest[:2] + "/" + digest + ".png", Kind: "skin", Model: "slim", Visibility: "public", ExpectedRevision: 0}
	foreign := p
	foreign.UserID = "other"
	if _, err = r.UploadTexture0252(ctx, foreign, input); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign update: %v", err)
	}
	selected, err := r.UploadTexture0252(ctx, p, input)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Revision != 1 || selected.Source != "managed-upload" || selected.BlobDigest != digest {
		t.Fatalf("invalid assignment: %+v", selected)
	}
	if _, err = r.UploadTexture0252(ctx, p, input); !errors.Is(err, ErrTextureRevisionConflict0251) {
		t.Fatalf("create replay: %v", err)
	}
	got, exists, err := r.ReadTextureProfile0251(ctx, p.UUID)
	if err != nil || !exists || got.SkinURL != "https://launcher.example/api/v1/textures/blob/"+digest || got.Model != "slim" {
		t.Fatalf("public texture: %+v %v", got, err)
	}
	if _, found, err := r.ReadTextureBlob0252(ctx, digest, model.MinecraftProfile{}, false); err != nil || !found {
		t.Fatalf("public access: %v, %v", found, err)
	}
	input.ExpectedRevision = 1
	input.Visibility = "private"
	input.Model = "classic"
	changed, err := r.UploadTexture0252(ctx, p, input)
	if err != nil || changed.Revision != 2 {
		t.Fatalf("replacing assignment: %+v %v", changed, err)
	}
	got, _, err = r.ReadTextureProfile0251(ctx, p.UUID)
	if err != nil || got.SkinURL != "" {
		t.Fatalf("private leak: %+v %v", got, err)
	}
	if _, found, err := r.ReadTextureBlob0252(ctx, digest, model.MinecraftProfile{}, false); err != nil || found {
		t.Fatalf("public read of private object: %v %v", found, err)
	}
	if _, found, err := r.ReadTextureBlob0252(ctx, digest, p, true); err != nil || !found {
		t.Fatalf("owner read: %v %v", found, err)
	}
	if _, found, err := r.ReadTextureBlob0252(ctx, digest, foreign, true); err != nil || found {
		t.Fatalf("foreign read: %v %v", found, err)
	}
	input.Kind = "cape"
	input.ExpectedRevision = 0
	input.Model = "classic"
	if _, err = r.UploadTexture0252(ctx, p, input); !errors.Is(err, ErrTextureUploadDenied0252) {
		t.Fatalf("unauthorized cape: %v", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO texture_cape_grants(project_id,user_id,granted,actor_user_id) VALUES('','owner',true,'other')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.UploadTexture0252(ctx, p, input); err != nil {
		t.Fatalf("cape after grant: %v", err)
	}
	revisions, err := r.ListTextureRevisions0251(ctx, p, "skin")
	if err != nil || len(revisions) != 2 || revisions[0].Event != "upload" {
		t.Fatalf("upload revision audit: %+v %v", revisions, err)
	}
}

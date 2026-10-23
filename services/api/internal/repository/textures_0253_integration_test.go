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

func TestTextureStorageQuota0253(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_0253")
	if dsn == "" {
		t.Skip("set TEST_PG_DSN_0253 to a disposable PostgreSQL database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	schema := fmt.Sprintf("texture_storage_0253_%d", time.Now().UnixNano())
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
 INSERT INTO minecraft_profiles VALUES('11111111-2222-4333-8444-555555555555','owner','Steve'),('99999999-2222-4333-8444-555555555555','other','Alex');`
	if _, err = db.ExecContext(ctx, setup); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0067_texture_identity_0251.sql", "0068_texture_upload_0252.sql", "0069_texture_storage_0253.sql", "0070_texture_fetch_0254.sql", "0071_texture_service_0255.sql"} {
		bytes, err := os.ReadFile("../dbmigrate/sql/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, string(bytes)); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO texture_project_policies(project_id,max_bytes_per_player,max_blobs_per_player)
 VALUES('',1024,1)`); err != nil {
		t.Fatal(err)
	}
	repo := &SQLRepository{db: db}
	owner := model.MinecraftProfile{UUID: "11111111-2222-4333-8444-555555555555", UserID: "owner", Name: "Steve", Realm: "local", Issuer: "neverlauncher"}
	makeUpload := func(content string, revision int64) VerifiedTexture0252 {
		sha := sha256.Sum256([]byte(content))
		digest := hex.EncodeToString(sha[:])
		return VerifiedTexture0252{Digest: digest, Size: int64(len(content)), Width: 64, Height: 64, Driver: "local", ObjectKey: "texture-blobs/sha256/" + digest[:2] + "/" + digest + ".png", Kind: "skin", Model: "classic", Visibility: "public", ExpectedRevision: revision}
	}
	a := makeUpload("first verified normalized png", 0)
	if err = repo.StageTextureUpload0253(ctx, owner, a); err != nil {
		t.Fatalf("staging: %v", err)
	}
	var stagedStatus string
	if err = db.QueryRowContext(ctx, `SELECT status FROM texture_blobs WHERE digest=$1`, a.Digest).Scan(&stagedStatus); err != nil || stagedStatus != "staging" {
		t.Fatalf("expected staged object: %s %v", stagedStatus, err)
	}
	if _, err = repo.UploadTexture0252(ctx, owner, a); err != nil {
		t.Fatal(err)
	}
	if err = repo.StageTextureUpload0253(ctx, owner, makeUpload("second verified normalized png", 1)); !errors.Is(err, ErrTextureUploadLimit0252) {
		t.Fatalf("staging must enforce quota: %v", err)
	}
	if _, err = repo.UploadTexture0252(ctx, owner, makeUpload("second verified normalized png", 1)); !errors.Is(err, ErrTextureUploadLimit0252) {
		t.Fatalf("expected count quota rejection, got %v", err)
	}
	// Identical digest is deduplicated, not charged twice even when replaced.
	a.ExpectedRevision = 1
	if _, err = repo.UploadTexture0252(ctx, owner, a); err != nil {
		t.Fatalf("deduped upload: %v", err)
	}
	var ownerCount int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM texture_blob_owners WHERE user_id='owner'`).Scan(&ownerCount); err != nil || ownerCount != 1 {
		t.Fatalf("quota owner rows %d %v", ownerCount, err)
	}
	// A second owner gets an independent ownership/quota record for the same content.
	other := model.MinecraftProfile{UUID: "99999999-2222-4333-8444-555555555555", UserID: "other", Name: "Alex", Realm: "local", Issuer: "neverlauncher"}
	a.ExpectedRevision = 0
	if err = repo.StageTextureUpload0253(ctx, other, a); err != nil {
		t.Fatalf("second owner staging dedup: %v", err)
	}
	if _, err = repo.UploadTexture0252(ctx, other, a); err != nil {
		t.Fatal(err)
	}
	var blobCount int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM texture_blobs`).Scan(&blobCount); err != nil || blobCount != 1 {
		t.Fatalf("expected physical dedup %d %v", blobCount, err)
	}
	// Referenced blobs cannot be GC candidates regardless of object age.
	if _, err = db.ExecContext(ctx, `UPDATE texture_blobs SET created_at=now()-interval '30 days', last_upload_at=now()-interval '30 days'`); err != nil {
		t.Fatal(err)
	}
	candidates, err := repo.ClaimTextureGarbage0253(ctx, "local", 50)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("GC must preserve assigned blob: %+v %v", candidates, err)
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM texture_assignments`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE texture_assignment_revisions SET created_at=now()-interval '30 days'`); err != nil {
		t.Fatal(err)
	}
	candidates, err = repo.ClaimTextureGarbage0253(ctx, "local", 50)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("expected orphan GC candidate: %+v %v", candidates, err)
	}
	if err = repo.FinishTextureGarbage0253(ctx, candidates[0].Digest); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM texture_blob_owners`).Scan(&ownerCount); err != nil || ownerCount != 0 {
		t.Fatalf("GC did not release quotas: %d %v", ownerCount, err)
	}
}

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

func TestTextureURLImportProvenance0254(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_0254")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL and TEST_PG_DSN_0254")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	schema := fmt.Sprintf("texture_fetch_0254_%d", time.Now().UnixNano())
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
		contents, e := os.ReadFile("../dbmigrate/sql/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(contents)); e != nil {
			t.Fatalf("migration %s: %v", name, e)
		}
	}
	repo := &SQLRepository{db: db}
	owner := model.MinecraftProfile{UUID: "11111111-2222-4333-8444-555555555555", UserID: "owner", Name: "Steve", Realm: "local", Issuer: "neverlauncher"}
	content := []byte("verified-normalized-png-bytes")
	hash := sha256.Sum256(content)
	digest := hex.EncodeToString(hash[:])
	input := VerifiedTexture0252{Digest: digest, Width: 64, Height: 64, Size: int64(len(content)), Driver: "local", ObjectKey: "texture-blobs/sha256/" + digest[:2] + "/" + digest + ".png", Kind: "skin", Model: "classic", Visibility: "public", ExpectedRevision: 0, Source: "managed-url-import"}
	if err = repo.StageTextureUpload0253(ctx, owner, input); err != nil {
		t.Fatal(err)
	}
	selected, err := repo.UploadTexture0252(ctx, owner, input)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Source != "managed-url-import" || selected.ExternalURL != "" || selected.BlobDigest != digest {
		t.Fatalf("unexpected import selection: %+v", selected)
	}
	var event, source, external string
	if err = db.QueryRowContext(ctx, `SELECT r.event,a.source,a.external_url FROM texture_assignment_revisions r JOIN texture_assignments a ON r.assignment_id=a.id WHERE a.id=$1`, selected.ID).Scan(&event, &source, &external); err != nil {
		t.Fatal(err)
	}
	if event != "import" || source != "managed-url-import" || external != "" {
		t.Fatalf("incorrect imported revision %s %s %s", event, source, external)
	}
	// Same digest remains immutable, and second request must pass a fresh CAS revision.
	if _, err = repo.UploadTexture0252(ctx, owner, input); !errors.Is(err, ErrTextureRevisionConflict0251) {
		t.Fatalf("expected stale revision conflict: %v", err)
	}
	alien := owner
	alien.UserID = "other"
	if _, err = repo.UploadTexture0252(ctx, alien, input); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign profile was writable: %v", err)
	}
	input.Source = "url-direct"
	input.ExpectedRevision = 1
	if _, err = repo.UploadTexture0252(ctx, owner, input); err == nil {
		t.Fatal("unsupported source was accepted")
	}
}

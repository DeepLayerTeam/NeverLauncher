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
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Run with TEST_PG_DSN_0251 pointing to an isolated PostgreSQL 17+ test DB.
// This test creates and drops its OWN schema; it executes against public.
func TestTextureIdentityAndRevisionPostgres0251(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_0251")
	if dsn == "" {
		t.Skip("TEST_PG_DSN_0251 not provided")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("test_textures_0251_%d", time.Now().UnixNano())
	if !regexp.MustCompile(`^test_textures_0251_[0-9]+$`).MatchString(schema) {
		t.Fatal("unsafe schema name")
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	setup := `CREATE TABLE users(id TEXT PRIMARY KEY);
    CREATE TABLE minecraft_profiles(uuid TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL);
    CREATE TABLE server_bridge_textures_v2(player_uuid TEXT PRIMARY KEY,username TEXT NOT NULL,skin_url TEXT NOT NULL,cape_url TEXT NOT NULL,model TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL);`
	if _, err := db.ExecContext(ctx, setup); err != nil {
		t.Fatal(err)
	}
	p := model.MinecraftProfile{UUID: "11111111-2222-4333-8444-555555555555", UserID: "account_a", Name: "AccountA", Realm: "local", Issuer: "launcher"}
	other := model.MinecraftProfile{UUID: "99999999-aaaa-4bbb-8ccc-dddddddddddd", UserID: "account_b", Name: "AccountB", Realm: "local", Issuer: "launcher"}
	if _, err = db.ExecContext(ctx, `INSERT INTO users(id) VALUES ('account_a'),('account_b')`); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO minecraft_profiles(uuid,user_id,name) VALUES ($1,$2,$3),($4,$5,$6)`, p.UUID, p.UserID, p.Name, other.UUID, other.UserID, other.Name)
	if err != nil {
		t.Fatal(err)
	}
	legacySum := playerDerivedHashForTest0251(p.UserID)
	_, err = db.ExecContext(ctx, `INSERT INTO server_bridge_textures_v2 VALUES ($1,'OldName','https://textures.example/skin.png','', 'slim', now()), ('22222222-2222-4222-8222-222222222222','Orphan','https://textures.example/orphan.png','','classic',now())`, legacySum)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../dbmigrate/sql/0067_texture_identity_0251.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("migration: %v", err)
	}
	r := &SQLRepository{db: db}
	selected, ok, err := r.ReadTextureProfile0251(ctx, p.UUID)
	if err != nil || !ok || selected.Model != "slim" || selected.SkinURL != "https://textures.example/skin.png" {
		t.Fatalf("migration lookup: %+v %v %v", selected, ok, err)
	}
	aliased, ok, err := r.ReadTextureProfile0251(ctx, legacySum)
	if err != nil || !ok || aliased.UUID != p.UUID {
		t.Fatalf("legacy alias: %+v %v %v", aliased, ok, err)
	}
	if _, ok, err := r.ReadTextureProfile0251(ctx, "22222222-2222-4222-8222-222222222222"); err != nil || ok {
		t.Fatalf("unmatched record unexpectedly resolved: %v %v", ok, err)
	}
	var unmatched int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM texture_legacy_unmatched`).Scan(&unmatched); err != nil || unmatched != 1 {
		t.Fatalf("quarantine count %d %v", unmatched, err)
	}
	list, err := r.ListTextureAssignments0251(ctx, p)
	if err != nil || len(list) != 1 || list[0].Revision != 1 {
		t.Fatalf("initial list %+v %v", list, err)
	}
	foreign := p
	foreign.UserID = other.UserID
	if _, err := r.UpdateTextureSelection0251(ctx, foreign, "skin", 1, "classic", "public", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign ownership accepted: %v", err)
	}
	changed, err := r.UpdateTextureSelection0251(ctx, p, "skin", 1, "classic", "private", true)
	if err != nil || changed.Revision != 2 {
		t.Fatalf("revision update %+v %v", changed, err)
	}
	if _, err := r.UpdateTextureSelection0251(ctx, p, "skin", 1, "slim", "public", true); !errors.Is(err, ErrTextureRevisionConflict0251) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	// Deny cape activation until an explicit grant; then allow it.
	if _, err := db.ExecContext(ctx, `INSERT INTO texture_assignments(realm,profile_uuid,user_id,kind,external_url,source,model)
      VALUES ('local-project',$1,$2,'cape','https://textures.example/cape.png','remote-reference','classic')`, p.UUID, p.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.UpdateTextureSelection0251(ctx, p, "cape", 1, "classic", "public", true); !errors.Is(err, ErrTextureCapeDenied0251) {
		t.Fatalf("cape policy bypass %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO texture_cape_grants(project_id,user_id,granted,actor_user_id) VALUES ('',$1,true,$2)`, p.UserID, other.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.UpdateTextureSelection0251(ctx, p, "cape", 1, "classic", "public", true); err != nil {
		t.Fatalf("granted cape rejected: %v", err)
	}
	nowPrivate, ok, err := r.ReadTextureProfile0251(ctx, p.UUID)
	if err != nil || !ok || nowPrivate.SkinURL != "" {
		t.Fatalf("private texture leaked: %+v %v %v", nowPrivate, ok, err)
	}
	history, err := r.ListTextureRevisions0251(ctx, p, "skin")
	if err != nil || len(history) != 2 || history[0].Revision != 2 || history[1].Revision != 1 {
		t.Fatalf("history %+v %v", history, err)
	}
	if err := r.EnsureTextureIdentity0251(ctx, p); err != nil {
		t.Fatal(err)
	}
	history, err = r.ListTextureRevisions0251(ctx, p, "skin")
	if err != nil || len(history) != 2 {
		t.Fatalf("lazy backfill reinserted revisions: %v %v", len(history), err)
	}
	// Ensure no zero-owner record can sneak past ownership checks.
	fake := p
	fake.UserID = "account_b"
	if err := r.EnsureTextureIdentity0251(ctx, fake); err == nil {
		t.Fatal("foreign canonical profile accepted")
	}
}

func playerDerivedHashForTest0251(userID string) string {
	sum := sha256.Sum256([]byte("launcher-player:" + userID))
	h := hex.EncodeToString(sum[:16])
	return strings.Join([]string{h[:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

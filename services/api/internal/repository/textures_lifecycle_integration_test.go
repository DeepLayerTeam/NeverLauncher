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
)

// Against a disposable PostgreSQL 17+ database, exercises real row locks,
// pinned backups, lease fencing, stale workers and quarantine lifecycle.
func TestTextureLifecyclePostgres02511(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN_02511")
	if dsn == "" {
		t.Skip("TEST_PG_DSN_02511 not provided")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(3)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("texture_lifecycle_02511_%d", time.Now().UnixNano())
	if !regexp.MustCompile(`^texture_lifecycle_02511_[0-9]+$`).MatchString(schema) {
		t.Fatal("invalid schema")
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	// One connection serializes the migration and test and preserves search_path.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE users(id TEXT PRIMARY KEY);
 CREATE TABLE minecraft_profiles(uuid TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL);
 CREATE TABLE server_bridge_textures_v2(player_uuid TEXT PRIMARY KEY,username TEXT NOT NULL,skin_url TEXT NOT NULL,cape_url TEXT NOT NULL,model TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{
		"0067_texture_identity_0251.sql", "0068_texture_upload_0252.sql", "0069_texture_storage_0253.sql",
		"0070_texture_fetch_0254.sql", "0071_texture_service_0255.sql", "0072_texture_admin_0259.sql",
		"0073_texture_gravit_import_02510.sql", "0074_texture_lifecycle_recovery_02511.sql",
	} {
		content, e := os.ReadFile("../dbmigrate/sql/" + filename)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(content)); e != nil {
			t.Fatalf("apply %s: %v", filename, e)
		}
	}
	digest := func(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
	a, b := digest("first"), digest("second")
	for _, d := range []string{a, b} {
		key := "texture-blobs/sha256/" + d[:2] + "/" + d + ".png"
		if _, err = db.ExecContext(ctx, `INSERT INTO texture_blobs(digest,byte_size,width,height,media_type,storage_driver,object_key,status,verified_at,created_at,last_upload_at)
   VALUES($1,5,64,64,'image/png','local',$2,'verified',now()-interval '30 days',now()-interval '30 days',now()-interval '30 days')`, d, key); err != nil {
			t.Fatal(err)
		}
	}
	r := &SQLRepository{db: db}
	pin, rows, err := r.BeginTextureSnapshot02511(ctx, "local")
	if err != nil || len(rows) != 2 {
		t.Fatalf("snapshot: rows=%d err=%v", len(rows), err)
	}
	if claims, err := r.ClaimTextureGarbage02511(ctx, "local", 50); err != nil || len(claims) != 0 {
		t.Fatalf("GC violated backup pin: %+v %v", claims, err)
	}
	if err := r.EndTextureSnapshot02511(ctx, pin); err != nil {
		t.Fatal(err)
	}
	claims, err := r.ClaimTextureGarbage02511(ctx, "local", 50)
	if err != nil || len(claims) != 2 {
		t.Fatalf("GC claim %d %v", len(claims), err)
	}
	first := claims[0]
	if err := r.CheckTextureGCLease02511(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := r.FinishTextureGC02511(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := r.FinishTextureGC02511(ctx, first); err == nil {
		t.Fatal("replayed GC finish accepted")
	}
	second := claims[1]
	if _, err := db.ExecContext(ctx, `UPDATE texture_blobs SET gc_claimed_at=now()-interval '46 minutes' WHERE digest=$1`, second.Digest); err != nil {
		t.Fatal(err)
	}
	recovered, err := r.ClaimTextureGarbage02511(ctx, "local", 1)
	if err != nil || len(recovered) != 1 {
		t.Fatalf("failed to reclaim stale GC: %+v %v", recovered, err)
	}
	if recovered[0].Token == second.Token {
		t.Fatal("reused GC token")
	}
	if err := r.CheckTextureGCLease02511(ctx, second); err == nil {
		t.Fatal("stale GC worker validated")
	}
	if err := r.FinishTextureGC02511(ctx, second); err == nil {
		t.Fatal("stale GC worker deleted replacement lease")
	}
	if err := r.ReleaseTextureGC02511(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckTextureGCLease02511(ctx, recovered[0]); err != nil {
		t.Fatal("stale release affected new worker", err)
	}
	if err := r.ReleaseTextureGC02511(ctx, recovered[0]); err != nil {
		t.Fatal(err)
	}
	newClaims, err := r.ClaimTextureGarbage02511(ctx, "local", 1)
	if err != nil || len(newClaims) != 1 {
		t.Fatalf("released row not reclaimed: %+v %v", newClaims, err)
	}
	if err := r.FinishTextureGC02511(ctx, newClaims[0]); err != nil {
		t.Fatal(err)
	}
	token, _, err := r.BeginTextureSnapshot02511(ctx, "local")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.EndTextureSnapshot02511(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PruneTextureSnapshotPins02511(ctx); err != nil {
		t.Fatal(err)
	}
	// 0.25.12: a simulated storage failure must leave the GC record intact.
	third := digest("third")
	key := "texture-blobs/sha256/" + third[:2] + "/" + third + ".png"
	if _, err = db.ExecContext(ctx, `INSERT INTO texture_blobs(digest,byte_size,width,height,media_type,storage_driver,object_key,status,verified_at,created_at,last_upload_at)
 VALUES($1,5,64,64,'image/png','local',$2,'verified',now()-interval '30 days',now()-interval '30 days',now()-interval '30 days')`, third, key); err != nil {
		t.Fatal(err)
	}
	candidateRows, err := r.ClaimTextureGarbage02511(ctx, "local", 1)
	if err != nil || len(candidateRows) != 1 {
		t.Fatalf("0.25.12 GC claim: %+v %v", candidateRows, err)
	}
	gc := candidateRows[0]
	called := 0
	if err := r.DeleteTextureWithLease02512(ctx, gc, func(context.Context, string) error { called++; return fmt.Errorf("storage unavailable") }); err == nil || called != 1 {
		t.Fatalf("storage failure lost: %v, called=%d", err, called)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM texture_blobs WHERE digest=$1`, third).Scan(&status); err != nil || status != "quarantined" {
		t.Fatalf("GC state lost on failed physical delete: %s %v", status, err)
	}
	bad := gc
	bad.Token = "a" + gc.Token[1:]
	if bad.Token == gc.Token {
		bad.Token = "b" + gc.Token[1:]
	}
	if err := r.DeleteTextureWithLease02512(ctx, bad, func(context.Context, string) error { called++; return nil }); err == nil || called != 1 {
		t.Fatal("stale lease executed physical deletion")
	}
	if err := r.DeleteTextureWithLease02512(ctx, gc, func(_ context.Context, digest string) error {
		called++
		if digest != third {
			return fmt.Errorf("wrong digest")
		}
		// A second PostgreSQL session must be unable to insert an FK
		// reference while the physical deletion is in progress. The
		// callback is deliberately invoked while the blob row is locked.
		secondDB, err := sql.Open("pgx", dsn)
		if err != nil {
			return err
		}
		defer secondDB.Close()
		lockCtx, stop := context.WithTimeout(ctx, 250*time.Millisecond)
		defer stop()
		_, err = secondDB.ExecContext(lockCtx, `INSERT INTO `+schema+`.texture_backup_pins(digest,lease_token,expires_at) VALUES ($1,$2,now()+interval '5 minutes')`, third, strings.Repeat("c", 64))
		if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("foreign-key insert bypassed GC row lock: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 2 {
		t.Fatal("physical delete callback not called exactly once on successful lease")
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM texture_blobs WHERE digest=$1)`, third).Scan(&exists); err != nil || exists {
		t.Fatalf("successful GC left blob row: %v %v", exists, err)
	}
	if err := r.DeleteTextureWithLease02512(ctx, gc, func(context.Context, string) error { called++; return nil }); err == nil || called != 2 {
		t.Fatal("replay accepted")
	}

}

//go:build !launcher_nopgx

package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Uses two distinct connections to prove live cross-replica visibility and the
// PostgreSQL 0.29.7 session cascade on a real protection ban.
func TestProtectionBanPostgres0298(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	uid := "protect-" + suffix
	session := "protect-sess-" + suffix
	family := "protect-family-" + suffix
	if _, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status) VALUES($1,$2,'Protection Test','player','active')`, uid, uid+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, uid)
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour')`, session, uid, uid+"@example.test", family); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, family, session, uid); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := b.SetProtectionBan(ctx, ProtectionBan{UserID: uid, Reason: "verified abuse", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := a.ActiveProtectionBan(ctx, uid, time.Now().UTC()); err != nil || !ok {
		t.Fatalf("replica did not see ban: %v %v", ok, err)
	}
	var state string
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id=$1`, session).Scan(&state); err != nil || state != "revoked" {
		t.Fatalf("ban did not revoke active session: %v %v", state, err)
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour')`, "post-ban-"+suffix, uid, uid+"@example.test", "post-family-"+suffix); err == nil || !strings.Contains(err.Error(), "protection policy denied") {
		t.Fatalf("new session admitted under ban: %v", err)
	}
	changed, err := b.RevokeProtectionBan(ctx, uid, "admin")
	if err != nil || !changed {
		t.Fatalf("unban failed %v %v", changed, err)
	}
	if _, ok, err := a.ActiveProtectionBan(ctx, uid, time.Now().UTC()); err != nil || ok {
		t.Fatalf("ban still active: %v %v", ok, err)
	}
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id=$1`, session).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("unban resurrected credentials")
	}
}

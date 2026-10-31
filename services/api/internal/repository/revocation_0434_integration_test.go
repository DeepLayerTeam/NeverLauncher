//go:build !launcher_nopgx

package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// A second API connection must observe revoked credentials without replica
// cache refresh, and SQL itself must reject attempts to restore tombstones.
func TestRevocationTerminalPostgres0434(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	uid, did, sid, fid := "revoke-user-"+suffix, "revoke-device-"+suffix, "revoke-session-"+suffix, "revoke-family-"+suffix
	mid := "revoke-mc-" + suffix
	email := uid + "@example.test"
	if _, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status) VALUES($1,$2,'Revocation Test','player','active')`, uid, email); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, uid)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pub)
	device := model.TrustedDevice{ID: did, UserID: uid, Name: "workstation", Status: "active", TrustState: "verified", PublicKey: base64.RawURLEncoding.EncodeToString(pub), KeyFingerprint: hex.EncodeToString(digest[:]), KeyAlgorithm: "ed25519"}
	if _, err := a.SaveTrustedDevice(ctx, device); err != nil {
		t.Fatal(err)
	}
	uuid := "04340000-0000-4000-8000-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)
	if _, err := a.db.ExecContext(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name) VALUES($1,$2,'Revoke0434')`, uid, uuid); err != nil {
		t.Fatal(err)
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at,trusted_device_id,device_trust_state,binding_epoch) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour',$5,'verified',1)`, sid, uid, email, fid, did); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, fid, sid, uid); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	credential := model.MinecraftSession{ID: mid, UserID: uid, NeverSessionID: sid, ProfileUUID: uuid, TrustedDeviceID: did, BindingEpoch: 1, AccessTokenHash: strings.Repeat("a", 64), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := a.SaveMinecraftSession(credential); err != nil {
		t.Fatal(err)
	}
	revoked, err := b.RevokeTrustedDevice(ctx, uid, did, "stolen-key")
	if err != nil || revoked.Device.Status != "revoked" {
		t.Fatalf("device revoke: %+v %v", revoked, err)
	}
	if revoked.RevokedSessions != 1 || revoked.RevokedMinecraftSessions != 1 ||
		len(revoked.RevokedSessionIDs) != 1 || revoked.RevokedSessionIDs[0] != sid {
		t.Fatalf("trigger cascade not reflected in API result: %+v", revoked)
	}
	var sessionState, minecraftState string
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id=$1`, sid).Scan(&sessionState); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM minecraft_sessions WHERE id=$1`, mid).Scan(&minecraftState); err != nil {
		t.Fatal(err)
	}
	if sessionState != "revoked" || minecraftState != "revoked" {
		t.Fatalf("cascade session=%s Minecraft=%s", sessionState, minecraftState)
	}
	if _, err := a.SaveTrustedDevice(ctx, device); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale device writer succeeded: %v", err)
	}
	if _, err := a.SaveMinecraftSession(credential); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Minecraft writer succeeded: %v", err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE trusted_devices SET status='active',trust_state='verified',revoked_at=NULL,revoked_reason='' WHERE id=$1`, did); err == nil {
		t.Fatal("SQL resurrected revoked device")
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE minecraft_sessions SET status='active',revoked_at=NULL,revoked_reason='' WHERE id=$1`, mid); err == nil {
		t.Fatal("SQL resurrected revoked game credential")
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE trusted_devices SET public_key=$2 WHERE id=$1`, did, base64.RawURLEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("SQL replaced key in revoked row")
	}
	again, err := a.GetTrustedDevice(uid, did)
	if err != nil || again.Status != "revoked" {
		t.Fatalf("device tombstone altered %+v %v", again, err)
	}
}

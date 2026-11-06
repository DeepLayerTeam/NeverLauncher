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
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Выполняет производственную транзакцию на одноразовой БД PostgreSQL. В
// частности, SQL-триггер tombstone 0.43.4 должен разрешать только установку
// ссылки замены и никогда не допускать повторную активацию отозванного ключа.
func TestRevokedDeviceRecoveryTransactionPostgres0435(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("требуется одноразовая база в LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, oldID := "recovery-user-"+suffix, "recovery-old-"+suffix
	sessionID, familyID := "recovery-session-"+suffix, "recovery-family-"+suffix
	email := userID + "@example.test"
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status) VALUES($1,$2,'Recovery Test','player','active')`, userID, email); err != nil {
		t.Fatal(err)
	}
	defer repo.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	oldPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest := sha256.Sum256(oldPublic)
	old := model.TrustedDevice{ID: oldID, UserID: userID, Name: "Lost key", Status: "active", TrustState: "verified", KeyAlgorithm: "ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(oldPublic), KeyFingerprint: hex.EncodeToString(oldDigest[:])}
	if _, err := repo.SaveTrustedDevice(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeTrustedDevice(ctx, userID, oldID, "stolen-device"); err != nil {
		t.Fatal(err)
	}
	tx, err := repo.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at,trusted_device_id,device_trust_state,binding_epoch) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour',NULL,'unverified',1)`, sessionID, userID, email, familyID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, familyID, sessionID, userID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	nextPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextHash := sha256.Sum256(nextPublic)
	next := model.TrustedDevice{ID: "recovery-new-" + suffix, UserID: userID, Name: "New key", Status: "active", TrustState: "verified", KeyAlgorithm: "ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(nextPublic), KeyFingerprint: hex.EncodeToString(nextHash[:])}
	// Разрешение passkey, выданное до отзыва, нельзя переносить в восстановление.
	if _, err := repo.db.ExecContext(ctx, `UPDATE auth_sessions SET auth_time=now()-interval '1 hour' WHERE id=$1`, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReplaceTrustedDeviceKey(ctx, userID, oldID, sessionID, "recover", "premature-recover", next, time.Now().UTC()); !errors.Is(err, ErrConflict) {
		t.Fatalf("Аутентификация до отзыва ошибочно принята: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE auth_sessions SET auth_time=now() WHERE id=$1`, sessionID); err != nil {
		t.Fatal(err)
	}
	result, err := repo.ReplaceTrustedDeviceKey(ctx, userID, oldID, sessionID, "recover", "device-key-recover", next, time.Now().UTC())
	if err != nil {
		t.Fatalf("recovery transaction: %v", err)
	}
	if result.OldDevice.Status != "revoked" || result.OldDevice.ReplacedByDeviceID != next.ID || result.NewDevice.AttestationState != "unattested" {
		t.Fatalf("recovery incorrectly reused old trust: %+v", result)
	}
	var savedID, trust, status string
	var epoch int64
	if err := repo.db.QueryRowContext(ctx, `SELECT trusted_device_id,device_trust_state,status,binding_epoch FROM auth_sessions WHERE id=$1`, sessionID).Scan(&savedID, &trust, &status, &epoch); err != nil {
		t.Fatal(err)
	}
	if savedID != next.ID || trust != "verified" || status != "active" || epoch <= 1 {
		t.Fatalf("rebound session not committed: %s %s %s %d", savedID, trust, status, epoch)
	}
	replayPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(replayPublic)
	replay := model.TrustedDevice{ID: "replay-" + suffix, UserID: userID, Name: "Replay", Status: "active", TrustState: "verified", KeyAlgorithm: "ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(replayPublic), KeyFingerprint: hex.EncodeToString(digest[:])}
	if _, err := repo.ReplaceTrustedDeviceKey(ctx, userID, oldID, sessionID, "recover", "replay", replay, time.Now().UTC()); !errors.Is(err, ErrConflict) {
		t.Fatalf("already recovered tombstone accepted a second replacement: %v", err)
	}
	if _, err := repo.SaveTrustedDevice(ctx, old); !errors.Is(err, ErrConflict) {
		t.Fatalf("old key reactivated: %v", err)
	}
}

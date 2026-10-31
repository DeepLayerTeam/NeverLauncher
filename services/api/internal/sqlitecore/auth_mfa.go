package sqlitecore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// TOTP follows RFC6238 (HMAC-SHA1, 6 digits, 30s, +/- one time step).
// Plaintext seed is returned only during enrollment, stored exclusively as
// AES-256-GCM ciphertext with independent operator-owned key.
func (a *Auth) seal(secret []byte) ([]byte, error) {
	block, e := aes.NewCipher(a.key[:])
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return gcm.Seal(nonce, nonce, secret, []byte("Launcher/TOTP/0.32.3")), nil
}
func (a *Auth) unseal(ciphertext []byte) ([]byte, error) {
	block, e := aes.NewCipher(a.key[:])
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	n := gcm.NonceSize()
	if len(ciphertext) < n+gcm.Overhead() {
		return nil, ErrAuthentication
	}
	secret, e := gcm.Open(nil, ciphertext[:n], ciphertext[n:], []byte("Launcher/TOTP/0.32.3"))
	if e != nil {
		return nil, ErrAuthentication
	}
	return secret, nil
}
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	h := hmac.New(sha1.New, secret)
	_, _ = h.Write(msg[:])
	d := h.Sum(nil)
	i := int(d[len(d)-1] & 15)
	num := (binary.BigEndian.Uint32(d[i:i+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", num)
}
func checkTOTP(secret []byte, raw string, now time.Time, lastStep int64) (int64, bool) {
	if len(raw) != 6 {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	step := now.UTC().Unix() / 30
	for delta := int64(-1); delta <= 1; delta++ {
		candidate := step + delta
		if candidate <= lastStep {
			continue
		}
		expected := totpCode(secret, candidate)
		if subtle.ConstantTimeCompare([]byte(raw), []byte(expected)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}
func (a *Auth) checkedPasswordTx(ctx context.Context, q sqlitedurable.Executor, userID, password string) error {
	var hash, status string
	e := q.QueryRowContext(ctx, `SELECT password_hash,status FROM users WHERE id=?`, userID).Scan(&hash, &status)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrAuthentication
	}
	if e != nil {
		return e
	}
	if status != "active" || !localpassword.Verify(password, hash) {
		return ErrAuthentication
	}
	return nil
}
func (a *Auth) StartTOTP(ctx context.Context, userID, password string) (string, error) {
	seed := make([]byte, 20)
	if _, e := rand.Read(seed); e != nil {
		return "", e
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	encrypted, e := a.seal(seed)
	for i := range seed {
		seed[i] = 0
	}
	if e != nil {
		return "", e
	}
	e = a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := a.checkedPasswordTx(ctx, q, userID, password); e != nil {
			return e
		}
		var status string
		er := q.QueryRowContext(ctx, `SELECT status FROM mfa_totp WHERE user_id=?`, userID).Scan(&status)
		if er != nil && !errors.Is(er, sql.ErrNoRows) {
			return er
		}
		if er == nil && status == "active" {
			return ErrConflict
		}
		now := nowNS()
		if _, er = q.ExecContext(ctx, `INSERT INTO mfa_totp(user_id,status,secret_ciphertext,last_step,created_at,updated_at) VALUES(?,'pending',?,-1,?,?)
 ON CONFLICT(user_id) DO UPDATE SET secret_ciphertext=excluded.secret_ciphertext,status='pending',last_step=-1,updated_at=excluded.updated_at`, userID, encrypted, now, now); er != nil {
			return er
		}
		return recordAudit(ctx, q, audit(userID, "auth:mfa-start", userID))
	})
	if e != nil {
		return "", e
	}
	return encoded, nil
}

// ConfirmTOTP atomically enrolls MFA, issues recovery codes once and revokes
// all existing sessions. It returns codes only after a confirmed WAL commit.
func (a *Auth) ConfirmTOTP(ctx context.Context, userID, password, code string) ([]string, error) {
	codes := make([]string, 8)
	hashes := make([]string, 8)
	for i := range codes {
		b := make([]byte, 10)
		if _, e := rand.Read(b); e != nil {
			return nil, e
		}
		codes[i] = strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		hashes[i] = hashBearer(codes[i])
	}
	e := a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := a.checkedPasswordTx(ctx, q, userID, password); e != nil {
			return e
		}
		var cipher []byte
		var status string
		if e := q.QueryRowContext(ctx, `SELECT secret_ciphertext,status FROM mfa_totp WHERE user_id=?`, userID).Scan(&cipher, &status); e != nil {
			return notFound(e)
		}
		if status != "pending" {
			return ErrConflict
		}
		secret, e := a.unseal(cipher)
		if e != nil {
			return e
		}
		step, ok := checkTOTP(secret, code, time.Now().UTC(), -1)
		for i := range secret {
			secret[i] = 0
		}
		if !ok {
			return ErrMFARequired
		}
		now := nowNS()
		if _, e = q.ExecContext(ctx, `UPDATE mfa_totp SET status='active',last_step=?,updated_at=? WHERE user_id=? AND status='pending'`, step, now, userID); e != nil {
			return e
		}
		for i := range hashes {
			if _, e = q.ExecContext(ctx, `INSERT INTO mfa_recovery(code_hash,user_id,created_at) VALUES(?,?,?)`, hashes[i], userID, now); e != nil {
				return e
			}
		}
		// MFA enrollment upgrades authentication requirements immediately.
		if _, e = q.ExecContext(ctx, `UPDATE users SET auth_epoch=auth_epoch+1,updated_at=? WHERE id=?`, now, userID); e != nil {
			return e
		}
		if e = a.revokeUserTx(ctx, q, userID, "mfa-enrolled", now); e != nil {
			return e
		}
		return recordAudit(ctx, q, audit(userID, "auth:mfa-enabled", userID))
	})
	if e != nil {
		return nil, e
	}
	return codes, nil
}

// checkSecondFactorTx consumes a single-use recovery code or a unique TOTP
// time step, within the same transaction that creates the next auth session.
func (a *Auth) checkSecondFactorTx(ctx context.Context, q sqlitedurable.Executor, userID string, cipher []byte, raw string, last int64) (bool, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 6 {
		secret, e := a.unseal(cipher)
		if e != nil {
			return false, e
		}
		step, ok := checkTOTP(secret, raw, time.Now().UTC(), last)
		for i := range secret {
			secret[i] = 0
		}
		if ok {
			res, e := q.ExecContext(ctx, `UPDATE mfa_totp SET last_step=?,updated_at=? WHERE user_id=? AND status='active' AND last_step<?`, step, nowNS(), userID, step)
			if e != nil {
				return false, e
			}
			n, e := res.RowsAffected()
			return n == 1, e
		}
	}
	// Recovery codes use 80 bits of entropy, SHA256 at rest, and one atomic use.
	if len(raw) != 16 {
		return false, nil
	}
	if _, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(raw); e != nil {
		return false, nil
	}
	result, e := q.ExecContext(ctx, `UPDATE mfa_recovery SET used_at=? WHERE code_hash=? AND user_id=? AND used_at=0`, nowNS(), hashBearer(raw), userID)
	if e != nil {
		return false, e
	}
	n, e := result.RowsAffected()
	return n == 1, e
}

// DisableTOTP requires both a current password and a valid second factor.
// Revocation is committed alongside removal of MFA, never deferred.
func (a *Auth) DisableTOTP(ctx context.Context, userID, password, secondFactor string) error {
	return a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := a.checkedPasswordTx(ctx, q, userID, password); e != nil {
			return e
		}
		var cipher []byte
		var status string
		var last int64
		if e := q.QueryRowContext(ctx, `SELECT secret_ciphertext,status,last_step FROM mfa_totp WHERE user_id=?`, userID).Scan(&cipher, &status, &last); e != nil {
			return notFound(e)
		}
		if status != "active" {
			return ErrMFARequired
		}
		ok, e := a.checkSecondFactorTx(ctx, q, userID, cipher, secondFactor, last)
		if e != nil {
			return e
		}
		if !ok {
			return ErrMFARequired
		}
		if _, e = q.ExecContext(ctx, `DELETE FROM mfa_recovery WHERE user_id=?`, userID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `DELETE FROM mfa_totp WHERE user_id=?`, userID); e != nil {
			return e
		}
		now := nowNS()
		if _, e = q.ExecContext(ctx, `UPDATE users SET auth_epoch=auth_epoch+1,updated_at=? WHERE id=?`, now, userID); e != nil {
			return e
		}
		if e = a.revokeUserTx(ctx, q, userID, "mfa-disabled", now); e != nil {
			return e
		}
		return recordAudit(ctx, q, audit(userID, "auth:mfa-disabled", userID))
	})
}

// RecoveryRemaining counts unused recovery codes without exposing their hashes.
func (a *Auth) RecoveryRemaining(ctx context.Context, userID string) (int, error) {
	var n int
	e := a.repo.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT COUNT(*) FROM mfa_recovery WHERE user_id=? AND used_at=0`, userID).Scan(&n)
	})
	return n, e
}

// ChallengeTOTP exposes a testable pure implementation without storing seeds.
func totpAt(secretBase32 string, t time.Time) (string, error) {
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if e != nil {
		return "", e
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	if len(seed) < 16 {
		return "", errors.New("invalid TOTP seed length")
	}
	return totpCode(seed, t.UTC().Unix()/30), nil
}

package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type securityPostgres111 struct {
	db     *sql.DB
	secret string
}

func (p *securityPostgres111) loadMFA(userID string) (mfaRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var pendingCipher, activeCipher, status string
	var updated time.Time
	err := p.db.QueryRowContext(ctx, `SELECT pending_secret_ciphertext,active_secret_ciphertext,status,updated_at FROM mfa_methods WHERE user_id=$1 AND method_type='totp'`, userID).Scan(&pendingCipher, &activeCipher, &status, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return mfaRecord{Recovery: map[string]string{}}, nil
	}
	if err != nil {
		return mfaRecord{}, err
	}
	rec := mfaRecord{PendingSecret: decryptString950(p.secret, pendingCipher), ActiveSecret: decryptString950(p.secret, activeCipher), Enabled: status == "enabled", Recovery: map[string]string{}, UpdatedAt: updated}
	rows, err := p.db.QueryContext(ctx, `SELECT code_hash,status FROM recovery_codes WHERE user_id=$1`, userID)
	if err != nil {
		return mfaRecord{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, st string
		if err := rows.Scan(&hash, &st); err != nil {
			return mfaRecord{}, err
		}
		rec.Recovery[hash] = st
	}
	return rec, rows.Err()
}

func (p *securityPostgres111) saveMFA(userID string, rec mfaRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status := "disabled"
	if rec.Enabled {
		status = "enabled"
	} else if rec.PendingSecret != "" {
		status = "pending"
	}
	pending := encryptString950(p.secret, rec.PendingSecret)
	active := encryptString950(p.secret, rec.ActiveSecret)
	if rec.PendingSecret != "" && pending == "" {
		return errors.New("не удалось зашифровать pending TOTP secret")
	}
	if rec.ActiveSecret != "" && active == "" {
		return errors.New("не удалось зашифровать active TOTP secret")
	}
	methodID := "mfa-totp-" + userID
	_, err := p.db.ExecContext(ctx, `INSERT INTO mfa_methods(id,user_id,method_type,status,pending_secret_ciphertext,active_secret_ciphertext,created_at,updated_at) VALUES($1,$2,'totp',$3,$4,$5,now(),now()) ON CONFLICT(user_id,method_type) DO UPDATE SET status=EXCLUDED.status,pending_secret_ciphertext=EXCLUDED.pending_secret_ciphertext,active_secret_ciphertext=EXCLUDED.active_secret_ciphertext,updated_at=now()`, methodID, userID, status, pending, active)
	return err
}

func (p *securityPostgres111) startTOTPEnrollment(userID, secret string) error {
	rec, err := p.loadMFA(userID)
	if err != nil {
		return err
	}
	rec.PendingSecret = secret
	rec.UpdatedAt = time.Now().UTC()
	return p.saveMFA(userID, rec)
}

func (p *securityPostgres111) finishTOTPEnrollment(userID, code string) bool {
	rec, err := p.loadMFA(userID)
	if err != nil || rec.PendingSecret == "" || !verifyTOTPCode902(rec.PendingSecret, code, time.Now().UTC()) {
		return false
	}
	rec.ActiveSecret = rec.PendingSecret
	rec.PendingSecret = ""
	rec.Enabled = true
	rec.UpdatedAt = time.Now().UTC()
	return p.saveMFA(userID, rec) == nil
}

func (p *securityPostgres111) disableTOTP(userID, code string) bool {
	rec, err := p.loadMFA(userID)
	if err != nil || !rec.Enabled || !verifyTOTPCode902(rec.ActiveSecret, code, time.Now().UTC()) {
		return false
	}
	rec.Enabled = false
	rec.ActiveSecret = ""
	rec.PendingSecret = ""
	rec.UpdatedAt = time.Now().UTC()
	if err := p.saveMFA(userID, rec); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = p.db.ExecContext(ctx, `UPDATE recovery_codes SET status='revoked' WHERE user_id=$1 AND status='active'`, userID)
	return true
}

func (p *securityPostgres111) verifySecondFactor(userID, totp, recovery string) (bool, string) {
	rec, err := p.loadMFA(userID)
	if err != nil {
		return false, "mfa-store-unavailable"
	}
	if !rec.Enabled {
		return true, "mfa-not-enabled"
	}
	if verifyTOTPCode902(rec.ActiveSecret, totp, time.Now().UTC()) {
		return true, "totp-ok"
	}
	if p.consumeRecoveryCode(userID, recovery) {
		return true, "recovery-ok"
	}
	return false, "mfa-required"
}

func (p *securityPostgres111) generateRecoveryCodes(userID string, count int) ([]string, error) {
	if count <= 0 {
		return nil, errors.New("recovery code count должен быть > 0")
	}
	rec, err := p.loadMFA(userID)
	if err != nil {
		return nil, err
	}
	if !rec.Enabled {
		return nil, errors.New("TOTP не включён")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET status='revoked' WHERE user_id=$1 AND status='active'`, userID); err != nil {
		return nil, err
	}
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		token, err := randomToken("nlrec")
		if err != nil {
			return nil, err
		}
		code := normalizeRecoveryCode111(token)
		hash := hashSecurityToken902(code)
		id, err := randomToken("rec")
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id,user_id,method_id,code_hash,status,created_at) VALUES($1,$2,$3,$4,'active',now())`, id, userID, "mfa-totp-"+userID, hash); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

func (p *securityPostgres111) consumeRecoveryCode(userID, code string) bool {
	code = normalizeProvidedRecoveryCode111(code)
	if code == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, `UPDATE recovery_codes SET status='used',used_at=now() WHERE user_id=$1 AND code_hash=$2 AND status='active'`, userID, hashSecurityToken902(code))
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (p *securityPostgres111) summary() (enabled, pending, activeRecovery int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = p.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE status='enabled'),count(*) FILTER (WHERE status='pending') FROM mfa_methods WHERE method_type='totp'`).Scan(&enabled, &pending); err != nil {
		return
	}
	err = p.db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes WHERE status='active'`).Scan(&activeRecovery)
	return
}

func (p *securityPostgres111) importLegacyMFA(state securityState950) error {
	for userID, legacy := range state.MFA {
		rec := mfaRecord{PendingSecret: decryptString950(p.secret, legacy.PendingSecretEncrypted), ActiveSecret: decryptString950(p.secret, legacy.ActiveSecretEncrypted), Enabled: legacy.Enabled, Recovery: legacy.Recovery, UpdatedAt: legacy.UpdatedAt}
		if err := p.saveMFA(userID, rec); err != nil {
			return fmt.Errorf("migrate MFA %s: %w", userID, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			cancel()
			return err
		}
		for hash, status := range legacy.Recovery {
			id := "legacy-rec-" + hash
			if len(id) > 63 {
				id = id[:63]
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO recovery_codes(id,user_id,method_id,code_hash,status,created_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(code_hash) DO NOTHING`, id, userID, "mfa-totp-"+userID, hash, status)
			if err != nil {
				tx.Rollback()
				cancel()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			cancel()
			return err
		}
		cancel()
	}
	return nil
}

func normalizeRecoveryCode111(token string) string {
	return normalizeProvidedRecoveryCode111(token)
}

func normalizeProvidedRecoveryCode111(code string) string {
	// Preserve the exact 0.10.x normalization so existing codes continue to work.
	return stringsToUpperReplaceUnderscore111(code)
}

func stringsToUpperReplaceUnderscore111(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "_", "-")
	return strings.ToUpper(value)
}

func (p *securityPostgres111) totpEnabled(userID string) bool {
	rec, err := p.loadMFA(userID)
	return err == nil && rec.Enabled
}

func (p *securityPostgres111) ensurePasskeyMethod117(userID string, enabled bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO mfa_methods(id,user_id,method_type,status,created_at,updated_at) VALUES($1,$2,'passkey',$3,now(),now()) ON CONFLICT(user_id,method_type) DO UPDATE SET status=EXCLUDED.status,updated_at=now()`, "mfa-passkey-"+userID, userID, status)
	return err
}

func (p *securityPostgres111) generateRecoveryCodesForMethod117(userID string, count int, methodID string) ([]string, error) {
	if count <= 0 {
		return nil, errors.New("recovery code count должен быть > 0")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var active bool
	if err := p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_methods WHERE id=$1 AND user_id=$2 AND status='enabled')`, methodID, userID).Scan(&active); err != nil || !active {
		return nil, errors.New("MFA method не активен")
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET status='revoked' WHERE user_id=$1 AND status='active'`, userID); err != nil {
		return nil, err
	}
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		token, err := randomToken("nlrec")
		if err != nil {
			return nil, err
		}
		code := normalizeRecoveryCode111(token)
		id, err := randomToken("rec")
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id,user_id,method_id,code_hash,status,created_at) VALUES($1,$2,$3,$4,'active',now())`, id, userID, methodID, hashSecurityToken902(code)); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

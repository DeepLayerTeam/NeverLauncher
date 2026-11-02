package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// consumeImportedTOTP0474 enforces SQLite Core's one-use, monotonic TOTP
// counter on MFA methods imported by sqlitepg. PostgreSQL row locking prevents
// concurrent logins from accepting the same time step. Unmigrated users keep
// the preexisting securityPostgres111 path, including databases that have not
// received the optional Core migration columns.
func (p *securityPostgres111) consumeImportedTOTP0474(userID, code, secret string) (handled, ok bool) {
	if len(code) != 6 || secret == "" {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return true, false
	}
	defer tx.Rollback()
	var original, stepText, status string
	// to_jsonb works on both migrated and unmigrated schemas; missing properties
	// produce empty strings, so ordinary installations are not changed.
	err = tx.QueryRowContext(ctx, `SELECT status,COALESCE(to_jsonb(m)->>'core_original_status_0474',''),
 COALESCE(to_jsonb(m)->>'core_last_step_0474','-1') FROM mfa_methods m
 WHERE m.user_id=$1 AND m.method_type='totp' FOR UPDATE`, userID).Scan(&status, &original, &stepText)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false
	}
	if err != nil {
		return true, false
	}
	if original == "" {
		return false, false
	}
	if original != "active" || status != "enabled" {
		return true, false
	}
	last, err := strconv.ParseInt(stepText, 10, 64)
	if err != nil {
		return true, false
	}
	now := time.Now().UTC()
	for delta := int64(-1); delta <= 1; delta++ {
		step := now.Unix()/30 + delta
		if step <= last {
			continue
		}
		expected := currentTOTPCode902(secret, time.Unix(step*30, 0))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) != 1 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mfa_methods SET core_last_step_0474=$2 WHERE user_id=$1 AND method_type='totp'`, userID, step); err != nil {
			return true, false
		}
		if err = tx.Commit(); err != nil {
			return true, false
		}
		return true, true
	}
	return true, false
}

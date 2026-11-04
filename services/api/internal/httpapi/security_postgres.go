package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// consumeImportedTOTP0474 обеспечивает однократное использование и монотонность
// счётчика TOTP SQLite Core для MFA-методов, импортированных через sqlitepg.
// Блокировки строк PostgreSQL не позволяют параллельным входам принять один
// временной интервал. Пользователи без миграции продолжают использовать прежний
// путь securityPostgres111, включая БД без необязательных колонок миграции Core.
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
	// to_jsonb работает как с мигрированной, так и с исходной схемой; отсутствующие
	// свойства дают пустые строки, поэтому обычные установки не меняются.
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

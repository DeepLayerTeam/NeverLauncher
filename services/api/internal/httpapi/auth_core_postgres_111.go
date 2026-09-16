package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const authCoreSchema111 = "0.11.1"

type authSessionPostgres111 struct {
	db *sql.DB
}

// ConfigureAuthCore111 switches authentication state from process-local development
// storage to normalized PostgreSQL tables. PostgreSQL is mandatory whenever the
// repository itself is persistent; memory mode remains available only for dev/tests.
func ConfigureAuthCore111(cfg config.Config, state *RuntimeState) error {
	if state == nil || state.AuthSessions == nil || state.Security == nil || state.Passkeys == nil {
		return errors.New("auth core runtime state не инициализирован")
	}
	if isMemoryRepository950(cfg.RepositoryDriver) {
		return nil
	}
	driver := strings.TrimSpace(cfg.SQLDriver)
	if driver == "" {
		driver = "pgx"
	}
	if strings.TrimSpace(cfg.DatabaseDSN) == "" {
		return errors.New("auth core 0.11.1 требует NEVERLAUNCHER_DATABASE_DSN")
	}
	db, err := sql.Open(driver, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("auth core postgres open: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("auth core postgres ping: %w", err)
	}
	// Fail closed if migrations were disabled or did not create the normalized schema.
	for _, table := range []string{"auth_sessions", "refresh_token_families", "refresh_tokens", "mfa_methods", "recovery_codes", "auth_events", "webauthn_credentials", "webauthn_challenges", "mfa_policies"} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			db.Close()
			if err != nil {
				return fmt.Errorf("auth core schema check %s: %w", table, err)
			}
			return fmt.Errorf("auth core schema table %s отсутствует; примените database migrations", table)
		}
	}
	for _, column := range []string{"last_ip", "last_user_agent", "risk_state", "risk_reasons", "risk_updated_at", "device_renamed_at"} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='auth_sessions' AND column_name=$1)`, column).Scan(&exists); err != nil || !exists {
			db.Close()
			if err != nil {
				return fmt.Errorf("session management 2.0 schema check %s: %w", column, err)
			}
			return fmt.Errorf("auth_sessions.%s отсутствует; примените migration 0008_session_management_2_0118.sql", column)
		}
	}
	state.AuthSessions.persistent = &authSessionPostgres111{db: db}
	state.Security.persistent = &securityPostgres111{db: db, secret: cfg.AuthTokenSecret}
	state.Passkeys.persistent = &passkeyPostgres117{db: db}
	return nil
}

func (p *authSessionPostgres111) create(user model.User, r *http.Request, deviceID string) (authSessionRecord, string, error) {
	return p.createWithAuth(user, r, deviceID, []string{"password"}, "single-factor", time.Now().UTC(), "", "local")
}

func (p *authSessionPostgres111) createWithAuth(user model.User, r *http.Request, deviceID string, methods []string, strength string, authTime time.Time, identityID, provider string) (authSessionRecord, string, error) {
	methods, strength, authTime, provider = normalizeSessionAuth117(methods, strength, authTime, provider)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return authSessionRecord{}, "", err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		deviceID = "admin-panel"
	}
	sessionID, err := randomToken("sess")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	familyID, err := randomToken("rtf")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	refreshToken, err := randomToken("nlr")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	tokenID, err := randomToken("rti")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	expires := now.Add(refreshTokenTTL)
	record := authSessionRecord{ID: sessionID, UserID: user.ID, Email: user.Email, RoleID: user.RoleID, DeviceID: deviceID, Device: deviceID, Status: "active", RefreshHash: hashRefreshToken(refreshToken), RefreshFamily: familyID, AuthMethods: append([]string(nil), methods...), AuthStrength: strength, AuthTime: authTime, IdentityID: strings.TrimSpace(identityID), Provider: provider, CreatedAt: now, LastSeenAt: now, ExpiresAt: expires, IP: clientIP(r), UserAgent: r.UserAgent(), LastIP: clientIP(r), LastUserAgent: r.UserAgent(), RiskState: "normal", RiskReasons: []string{}, DeviceTrustState: "unverified"}

	methodsJSON, _ := json.Marshal(record.AuthMethods)
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,device_id,device,status,refresh_family_id,auth_methods,auth_strength,auth_time,identity_id,provider,created_at,last_seen_at,expires_at,ip,user_agent,last_ip,last_user_agent,risk_state,risk_reasons) VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8::jsonb,$9,$10,$11,$12,$13,$13,$14,$15,$16,$15,$16,'normal','[]'::jsonb)`, record.ID, record.UserID, record.Email, record.RoleID, record.DeviceID, record.Device, familyID, string(methodsJSON), record.AuthStrength, record.AuthTime, record.IdentityID, record.Provider, now, expires, record.IP, record.UserAgent); err != nil {
		return authSessionRecord{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id,status,created_at) VALUES($1,$2,$3,'active',$4)`, familyID, record.ID, user.ID, now); err != nil {
		return authSessionRecord{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens(id,family_id,session_id,token_hash,status,created_at,expires_at) VALUES($1,$2,$3,$4,'current',$5,$6)`, tokenID, familyID, record.ID, record.RefreshHash, now, expires); err != nil {
		return authSessionRecord{}, "", err
	}
	if err := p.enforceSessionLimitTx111(ctx, tx, user.ID); err != nil {
		return authSessionRecord{}, "", err
	}
	if err := p.insertEventTx111(ctx, tx, user.ID, record.ID, familyID, "session-created", map[string]any{"deviceId": deviceID}); err != nil {
		return authSessionRecord{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return authSessionRecord{}, "", err
	}
	return record, refreshToken, nil
}

func (p *authSessionPostgres111) rotate(refreshToken string) (authSessionRecord, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return authSessionRecord{}, "", err
	}
	defer tx.Rollback()

	hash := hashRefreshToken(refreshToken)
	var tokenID, familyID, sessionID, tokenStatus string
	var tokenExpires time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,family_id,session_id,status,expires_at FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE`, hash).Scan(&tokenID, &familyID, &sessionID, &tokenStatus, &tokenExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return authSessionRecord{}, "", errRefreshTokenInvalid
	}
	if err != nil {
		return authSessionRecord{}, "", err
	}
	if tokenStatus == "consumed" {
		if err := p.compromiseFamilyTx111(ctx, tx, familyID, sessionID, "refresh-token-reuse"); err != nil {
			return authSessionRecord{}, "", err
		}
		if err := tx.Commit(); err != nil {
			return authSessionRecord{}, "", err
		}
		return authSessionRecord{}, "", errRefreshTokenReuseDetected
	}
	if tokenStatus != "current" || tokenExpires.Before(time.Now().UTC()) {
		return authSessionRecord{}, "", errRefreshTokenInvalid
	}

	record, err := scanSession118(tx.QueryRowContext(ctx, `SELECT `+sessionColumns118+` FROM auth_sessions WHERE id=$1 FOR UPDATE`, sessionID))
	if err != nil || record.Status != "active" || record.ExpiresAt.Before(time.Now().UTC()) {
		if err == nil {
			now := time.Now().UTC()
			_, _ = tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason='expired-or-inactive-refresh-token' WHERE id=$1`, sessionID, now)
			_, _ = tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status IN ('current','consumed')`, familyID, now)
			_, _ = tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason='expired-or-inactive-refresh-token' WHERE id=$1`, familyID, now)
			_ = tx.Commit()
		}
		return authSessionRecord{}, "", errRefreshTokenInvalid
	}

	now := time.Now().UTC()
	newRefresh, err := randomToken("nlr")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	newHash := hashRefreshToken(newRefresh)
	newID, err := randomToken("rti")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	newExpires := now.Add(refreshTokenTTL)
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='consumed',consumed_at=$2,replaced_by_id=$3 WHERE id=$1 AND status='current'`, tokenID, now, newID); err != nil {
		return authSessionRecord{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens(id,family_id,session_id,token_hash,status,created_at,expires_at) VALUES($1,$2,$3,$4,'current',$5,$6)`, newID, familyID, sessionID, newHash, now, newExpires); err != nil {
		return authSessionRecord{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at=$2,expires_at=$3 WHERE id=$1`, sessionID, now, newExpires); err != nil {
		return authSessionRecord{}, "", err
	}
	if err := p.insertEventTx111(ctx, tx, record.UserID, sessionID, familyID, "refresh-rotated", map[string]any{"previousTokenId": tokenID, "newTokenId": newID}); err != nil {
		return authSessionRecord{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return authSessionRecord{}, "", err
	}
	record.RefreshHash = newHash
	record.LastSeenAt = now
	record.ExpiresAt = newExpires
	return record, newRefresh, nil
}

func (p *authSessionPostgres111) active(sessionID, userID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at=now() WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now()`, sessionID, userID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (p *authSessionPostgres111) get(sessionID, userID string) (authSessionRecord, bool) {
	return p.get118(sessionID, userID)
}

func (p *authSessionPostgres111) stepUp(sessionID, userID string, methods []string, strength string, authTime time.Time) (authSessionRecord, error) {
	methods, strength, authTime, _ = normalizeSessionAuth117(methods, strength, authTime, "local")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return authSessionRecord{}, err
	}
	defer tx.Rollback()
	rec, err := scanSession118(tx.QueryRowContext(ctx, `SELECT `+sessionColumns118+` FROM auth_sessions WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now() FOR UPDATE`, sessionID, userID))
	if err != nil {
		return authSessionRecord{}, errAuthRequired
	}
	rec.AuthMethods = mergeAuthMethods117(rec.AuthMethods, methods...)
	if authStrengthLevel117(strength) > authStrengthLevel117(rec.AuthStrength) {
		rec.AuthStrength = strength
	}
	rec.AuthTime = authTime
	raw, _ := json.Marshal(rec.AuthMethods)
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET auth_methods=$3::jsonb,auth_strength=$4,auth_time=$5,last_seen_at=now() WHERE id=$1 AND user_id=$2`, sessionID, userID, string(raw), rec.AuthStrength, rec.AuthTime); err != nil {
		return authSessionRecord{}, err
	}
	if err := p.insertEventTx111(ctx, tx, userID, sessionID, rec.RefreshFamily, "session-step-up", map[string]any{"authStrength": rec.AuthStrength, "authMethods": rec.AuthMethods}); err != nil {
		return authSessionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return authSessionRecord{}, err
	}
	rec.LastSeenAt = time.Now().UTC()
	return rec, nil
}

func (p *authSessionPostgres111) revoke(sessionID, reason string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	var familyID, userID string
	if err := tx.QueryRowContext(ctx, `SELECT refresh_family_id,user_id FROM auth_sessions WHERE id=$1 FOR UPDATE`, sessionID).Scan(&familyID, &userID); err != nil {
		return false
	}
	now := time.Now().UTC()
	reason = firstNonEmpty(reason, "manual-revoke")
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, sessionID, now, reason); err != nil {
		return false
	}
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, familyID, now, reason); err != nil {
		return false
	}
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, familyID, now); err != nil {
		return false
	}
	_ = p.insertEventTx111(ctx, tx, userID, sessionID, familyID, "session-revoked", map[string]any{"reason": reason})
	return tx.Commit() == nil
}

func (p *authSessionPostgres111) revokeUser(userID, reason string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	defer tx.Rollback()
	reason = firstNonEmpty(reason, "user-session-revoke")
	now := time.Now().UTC()
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE user_id=$1 AND status='active' FOR UPDATE`, userID)
	if err != nil {
		return 0
	}
	type item struct{ session, family string }
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.session, &it.family); err != nil {
			rows.Close()
			return 0
		}
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, it.session, now, reason); err != nil {
			return 0
		}
		_, _ = tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, it.family, now, reason)
		_, _ = tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, it.family, now)
		_ = p.insertEventTx111(ctx, tx, userID, it.session, it.family, "session-revoked", map[string]any{"reason": reason})
	}
	if err := tx.Commit(); err != nil {
		return 0
	}
	return len(items)
}

func (p *authSessionPostgres111) listByUser(userID string) []authSessionRecord {
	return p.listByUser118(userID)
}

func (p *authSessionPostgres111) summary() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var active, total int
	if err := p.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE status='active' AND expires_at>now()),count(*) FROM auth_sessions`).Scan(&active, &total); err != nil {
		return map[string]any{"backend": "postgres-auth-core-0.11.1", "status": "unavailable", "error": err.Error()}
	}
	return map[string]any{"active": active, "revokedOrExpired": total - active, "total": total, "backend": "postgres-auth-core-0.11.1", "sourceOfTruth": "PostgreSQL", "reuseDetection": "refresh-token-family"}
}

func (p *authSessionPostgres111) compromiseFamilyTx111(ctx context.Context, tx *sql.Tx, familyID, sessionID, reason string) error {
	now := time.Now().UTC()
	var userID string
	_ = tx.QueryRowContext(ctx, `SELECT user_id FROM refresh_token_families WHERE id=$1`, familyID).Scan(&userID)
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='compromised',compromised_at=$2,revoked_at=$2,revoked_reason=$3 WHERE id=$1`, familyID, now, reason); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3,risk_state='compromised',risk_reasons=jsonb_build_array($3),risk_updated_at=$2 WHERE id=$1`, sessionID, now, reason); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1`, familyID, now); err != nil {
		return err
	}
	return p.insertEventTx111(ctx, tx, userID, sessionID, familyID, "refresh-token-reuse-detected", map[string]any{"familyCompromised": true})
}

func (p *authSessionPostgres111) enforceSessionLimitTx111(ctx context.Context, tx *sql.Tx, userID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE user_id=$1 AND status='active' ORDER BY last_seen_at DESC OFFSET $2`, userID, maxSessionsPerUser)
	if err != nil {
		return err
	}
	defer rows.Close()
	type item struct{ session, family string }
	var stale []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.session, &it.family); err != nil {
			return err
		}
		stale = append(stale, it)
	}
	now := time.Now().UTC()
	for _, it := range stale {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason='max-sessions-per-user' WHERE id=$1`, it.session, now); err != nil {
			return err
		}
		_, _ = tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason='max-sessions-per-user' WHERE id=$1`, it.family, now)
		_, _ = tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, it.family, now)
	}
	return nil
}

func (p *authSessionPostgres111) insertEventTx111(ctx context.Context, tx *sql.Tx, userID, sessionID, familyID, eventType string, details map[string]any) error {
	raw, _ := json.Marshal(details)
	_, err := tx.ExecContext(ctx, `INSERT INTO auth_events(user_id,session_id,family_id,event_type,details,created_at) VALUES(NULLIF($1,''),NULLIF($2,''),NULLIF($3,''),$4,$5::jsonb,now())`, userID, sessionID, familyID, eventType, string(raw))
	return err
}

func (p *authSessionPostgres111) importLegacySessions(items []authSessionRecord) error {
	if len(items) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, rec := range items {
		if rec.ID == "" || rec.UserID == "" || rec.RefreshFamily == "" || rec.RefreshHash == "" {
			continue
		}
		status := firstNonEmpty(rec.Status, "active")
		methods, strength, authTime, provider := normalizeSessionAuth117(rec.AuthMethods, rec.AuthStrength, rec.AuthTime, rec.Provider)
		methodsJSON, _ := json.Marshal(methods)
		_, err = tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,device_id,device,status,refresh_family_id,auth_methods,auth_strength,auth_time,identity_id,provider,created_at,last_seen_at,expires_at,revoked_at,revoked_reason,ip,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$16,NULLIF($17,'0001-01-01T00:00:00Z')::timestamptz,$18,$19,$20) ON CONFLICT(id) DO NOTHING`, rec.ID, rec.UserID, rec.Email, rec.RoleID, rec.DeviceID, rec.Device, status, rec.RefreshFamily, string(methodsJSON), strength, authTime, rec.IdentityID, provider, rec.CreatedAt, rec.LastSeenAt, rec.ExpiresAt, rec.RevokedAt.UTC().Format(time.RFC3339), rec.RevokedReason, rec.IP, rec.UserAgent)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id,status,created_at,revoked_reason) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING`, rec.RefreshFamily, rec.ID, rec.UserID, status, rec.CreatedAt, rec.RevokedReason)
		if err != nil {
			return err
		}
		id := "legacy-" + rec.RefreshHash
		if len(id) > 63 {
			id = id[:63]
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO refresh_tokens(id,family_id,session_id,token_hash,status,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(token_hash) DO NOTHING`, id, rec.RefreshFamily, rec.ID, rec.RefreshHash, map[bool]string{true: "current", false: "revoked"}[status == "active"], rec.CreatedAt, rec.ExpiresAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

type rowScanner111 interface{ Scan(dest ...any) error }

func scanSession111(row rowScanner111) (authSessionRecord, error) {
	var rec authSessionRecord
	var revoked sql.NullTime
	var methodsJSON []byte
	if err := row.Scan(&rec.ID, &rec.UserID, &rec.Email, &rec.RoleID, &rec.DeviceID, &rec.Device, &rec.Status, &rec.RefreshFamily, &methodsJSON, &rec.AuthStrength, &rec.AuthTime, &rec.IdentityID, &rec.Provider, &rec.CreatedAt, &rec.LastSeenAt, &rec.ExpiresAt, &revoked, &rec.RevokedReason, &rec.IP, &rec.UserAgent); err != nil {
		return authSessionRecord{}, err
	}
	_ = json.Unmarshal(methodsJSON, &rec.AuthMethods)
	if len(rec.AuthMethods) == 0 {
		rec.AuthMethods = []string{"unknown"}
	}
	if revoked.Valid {
		rec.RevokedAt = revoked.Time
	}
	return rec, nil
}

// stableSessionSort111 is used by tests/compatibility callers that aggregate rows
// from more than one backend.
func stableSessionSort111(items []authSessionRecord) {
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeenAt.After(items[j].LastSeenAt) })
}

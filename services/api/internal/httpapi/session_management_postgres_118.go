package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

const sessionColumns118 = `id,user_id,email,role_id,device_id,device,status,refresh_family_id,auth_methods,auth_strength,auth_time,identity_id,provider,created_at,last_seen_at,expires_at,revoked_at,revoked_reason,ip,user_agent,last_ip,last_user_agent,risk_state,risk_reasons,risk_updated_at,device_renamed_at,trusted_device_id,device_trust_state,device_verified_at`

func scanSession118(row rowScanner111) (authSessionRecord, error) {
	var rec authSessionRecord
	var revoked, riskUpdated, renamed, deviceVerified sql.NullTime
	var trustedDeviceID sql.NullString
	var methodsJSON, riskJSON []byte
	if err := row.Scan(&rec.ID, &rec.UserID, &rec.Email, &rec.RoleID, &rec.DeviceID, &rec.Device, &rec.Status, &rec.RefreshFamily, &methodsJSON, &rec.AuthStrength, &rec.AuthTime, &rec.IdentityID, &rec.Provider, &rec.CreatedAt, &rec.LastSeenAt, &rec.ExpiresAt, &revoked, &rec.RevokedReason, &rec.IP, &rec.UserAgent, &rec.LastIP, &rec.LastUserAgent, &rec.RiskState, &riskJSON, &riskUpdated, &renamed, &trustedDeviceID, &rec.DeviceTrustState, &deviceVerified); err != nil {
		return authSessionRecord{}, err
	}
	_ = json.Unmarshal(methodsJSON, &rec.AuthMethods)
	_ = json.Unmarshal(riskJSON, &rec.RiskReasons)
	if len(rec.AuthMethods) == 0 {
		rec.AuthMethods = []string{"unknown"}
	}
	if rec.RiskReasons == nil {
		rec.RiskReasons = []string{}
	}
	rec.RiskState = normalizeRiskState118(rec.RiskState)
	if revoked.Valid {
		rec.RevokedAt = revoked.Time.UTC()
	}
	if riskUpdated.Valid {
		rec.RiskUpdatedAt = riskUpdated.Time.UTC()
	}
	if renamed.Valid {
		rec.DeviceRenamedAt = renamed.Time.UTC()
	}
	if trustedDeviceID.Valid {
		rec.TrustedDeviceID = trustedDeviceID.String
	}
	if rec.DeviceTrustState == "" {
		rec.DeviceTrustState = "unverified"
	}
	if deviceVerified.Valid {
		rec.DeviceVerifiedAt = deviceVerified.Time.UTC()
	}
	return rec, nil
}

func (p *authSessionPostgres111) observe118(sessionID, userID string, r *http.Request) (authSessionRecord, bool) {
	base := context.Background()
	if r != nil {
		base = r.Context()
	}
	ctx, cancel := context.WithTimeout(base, 3*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return authSessionRecord{}, false
	}
	defer tx.Rollback()
	rec, err := scanSession118(tx.QueryRowContext(ctx, `SELECT `+sessionColumns118+` FROM auth_sessions WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now() FOR UPDATE`, sessionID, userID))
	if err != nil {
		return authSessionRecord{}, false
	}
	now := time.Now().UTC()
	previousRisk := normalizeRiskState118(rec.RiskState)
	previousReasons := append([]string(nil), rec.RiskReasons...)
	if r != nil {
		applySessionObservation118(&rec, clientIP(r), r.UserAgent(), now)
	}
	riskJSON, _ := json.Marshal(rec.RiskReasons)
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at=$3,last_ip=$4,last_user_agent=$5,risk_state=$6,risk_reasons=$7::jsonb,risk_updated_at=NULLIF($8,'0001-01-01T00:00:00Z')::timestamptz WHERE id=$1 AND user_id=$2`, sessionID, userID, now, rec.LastIP, rec.LastUserAgent, rec.RiskState, string(riskJSON), rec.RiskUpdatedAt.UTC().Format(time.RFC3339)); err != nil {
		return authSessionRecord{}, false
	}
	if rec.RiskState != previousRisk || len(rec.RiskReasons) != len(previousReasons) {
		if err := p.insertEventTx111(ctx, tx, userID, sessionID, rec.RefreshFamily, "session-risk-elevated", map[string]any{"riskState": rec.RiskState, "reasons": rec.RiskReasons}); err != nil {
			return authSessionRecord{}, false
		}
	}
	if err := tx.Commit(); err != nil {
		return authSessionRecord{}, false
	}
	rec.LastSeenAt = now
	return sanitizeSessionRecord(rec), true
}

func (p *authSessionPostgres111) get118(sessionID, userID string) (authSessionRecord, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rec, err := scanSession118(p.db.QueryRowContext(ctx, `SELECT `+sessionColumns118+` FROM auth_sessions WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now()`, sessionID, userID))
	return sanitizeSessionRecord(rec), err == nil
}

func (p *authSessionPostgres111) listByUser118(userID string) []authSessionRecord {
	return p.listFiltered118(userID, "", "", "")
}

func (p *authSessionPostgres111) listFiltered118(userID, provider, status, risk string) []authSessionRecord {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	userID = strings.TrimSpace(userID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	status = strings.ToLower(strings.TrimSpace(status))
	risk = strings.ToLower(strings.TrimSpace(risk))
	rows, err := p.db.QueryContext(ctx, `SELECT `+sessionColumns118+` FROM auth_sessions WHERE ($1='' OR user_id=$1) AND ($2='' OR lower(provider)=$2) AND ($3='' OR lower(status)=$3) AND ($4='' OR risk_state=$4) ORDER BY last_seen_at DESC LIMIT 1000`, userID, provider, status, risk)
	if err != nil {
		return []authSessionRecord{}
	}
	defer rows.Close()
	out := []authSessionRecord{}
	for rows.Next() {
		if rec, err := scanSession118(rows); err == nil {
			out = append(out, sanitizeSessionRecord(rec))
		}
	}
	return out
}

func (p *authSessionPostgres111) renameDevice118(sessionID, userID, name string) (authSessionRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return authSessionRecord{}, err
	}
	defer tx.Rollback()
	rec, err := scanSession118(tx.QueryRowContext(ctx, `SELECT `+sessionColumns118+` FROM auth_sessions WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now() FOR UPDATE`, sessionID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return authSessionRecord{}, errSessionNotFound118
	}
	if err != nil {
		return authSessionRecord{}, err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET device=$3,device_renamed_at=$4 WHERE id=$1 AND user_id=$2`, sessionID, userID, name, now); err != nil {
		return authSessionRecord{}, err
	}
	if err := p.insertEventTx111(ctx, tx, userID, sessionID, rec.RefreshFamily, "session-device-renamed", map[string]any{"device": name}); err != nil {
		return authSessionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return authSessionRecord{}, err
	}
	rec.Device = name
	rec.DeviceRenamedAt = now
	return sanitizeSessionRecord(rec), nil
}

func (p *authSessionPostgres111) revokeOthers118(userID, currentSessionID, reason string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE user_id=$1 AND id<>$2 AND status='active' FOR UPDATE`, userID, currentSessionID)
	if err != nil {
		return 0
	}
	type item struct{ id, family string }
	items := []item{}
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.family) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	now := time.Now().UTC()
	reason = firstNonEmpty(reason, "user-revoke-other-sessions")
	for _, it := range items {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, it.id, now, reason); err != nil {
			return 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, it.family, now, reason); err != nil {
			return 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, it.family, now); err != nil {
			return 0
		}
		if err := p.insertEventTx111(ctx, tx, userID, it.id, it.family, "session-revoked", map[string]any{"reason": reason}); err != nil {
			return 0
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return len(items)
}

func (p *authSessionPostgres111) revokeFiltered118(userID, provider, risk, reason string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	userID = strings.TrimSpace(userID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	risk = strings.ToLower(strings.TrimSpace(risk))
	reason = firstNonEmpty(strings.TrimSpace(reason), "admin-session-revoke")
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id,user_id FROM auth_sessions WHERE status='active' AND ($1='' OR user_id=$1) AND ($2='' OR lower(provider)=$2) AND ($3='' OR risk_state=$3) FOR UPDATE`, userID, provider, risk)
	if err != nil {
		return 0
	}
	type item struct{ id, family, user string }
	items := []item{}
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.family, &it.user) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	now := time.Now().UTC()
	for _, it := range items {
		riskState := "normal"
		riskReasons := []string{}
		if strings.Contains(strings.ToLower(reason), "compromised") {
			riskState = "compromised"
			riskReasons = []string{reason}
		}
		raw, _ := json.Marshal(riskReasons)
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3,risk_state=CASE WHEN $4='compromised' THEN 'compromised' ELSE risk_state END,risk_reasons=CASE WHEN $4='compromised' THEN risk_reasons || $5::jsonb ELSE risk_reasons END,risk_updated_at=CASE WHEN $4='compromised' THEN $2 ELSE risk_updated_at END WHERE id=$1`, it.id, now, reason, riskState, string(raw)); err != nil {
			return 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, it.family, now, reason); err != nil {
			return 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, it.family, now); err != nil {
			return 0
		}
		if err := p.insertEventTx111(ctx, tx, it.user, it.id, it.family, "session-revoked", map[string]any{"reason": reason, "admin": true}); err != nil {
			return 0
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return len(items)
}

func (p *authSessionPostgres111) bindTrustedDevice121(sessionID, userID, deviceID string, verifiedAt time.Time) (authSessionRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return authSessionRecord{}, err
	}
	defer tx.Rollback()
	var familyID string
	if err := tx.QueryRowContext(ctx, `SELECT refresh_family_id FROM auth_sessions WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now() FOR UPDATE`, sessionID, userID).Scan(&familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authSessionRecord{}, errSessionNotFound118
		}
		return authSessionRecord{}, err
	}
	var owner, status string
	if err := tx.QueryRowContext(ctx, `SELECT user_id,status FROM trusted_devices WHERE id=$1 FOR SHARE`, deviceID).Scan(&owner, &status); err != nil {
		return authSessionRecord{}, err
	}
	if owner != userID || status != "active" {
		return authSessionRecord{}, errSessionNotFound118
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET trusted_device_id=$3,device_trust_state='verified',device_verified_at=$4,last_seen_at=now() WHERE id=$1 AND user_id=$2`, sessionID, userID, deviceID, verifiedAt.UTC()); err != nil {
		return authSessionRecord{}, err
	}
	if err := p.insertEventTx111(ctx, tx, userID, sessionID, familyID, "trusted-device-bound", map[string]any{"deviceId": deviceID}); err != nil {
		return authSessionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return authSessionRecord{}, err
	}
	rec, ok := p.get118(sessionID, userID)
	if !ok {
		return authSessionRecord{}, errSessionNotFound118
	}
	return rec, nil
}

func (p *authSessionPostgres111) revokeTrustedDevice121(userID, deviceID, reason string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reason = firstNonEmpty(strings.TrimSpace(reason), "device-revoked")
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE user_id=$1 AND trusted_device_id=$2 AND status='active' FOR UPDATE`, userID, deviceID)
	if err != nil {
		return 0
	}
	type item struct{ session, family string }
	items := []item{}
	for rows.Next() {
		var it item
		if rows.Scan(&it.session, &it.family) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	now := time.Now().UTC()
	for _, it := range items {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3,risk_state='compromised',risk_reasons=risk_reasons || jsonb_build_array($3),risk_updated_at=$2,device_trust_state='revoked' WHERE id=$1`, it.session, now, reason); err != nil {
			return 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, it.family, now, reason); err != nil {
			return 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, it.family, now); err != nil {
			return 0
		}
		if err := p.insertEventTx111(ctx, tx, userID, it.session, it.family, "trusted-device-revoked", map[string]any{"deviceId": deviceID, "reason": reason}); err != nil {
			return 0
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return len(items)
}

func (p *authSessionPostgres111) summary118() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var active, total, elevated, compromised int
	err := p.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE status='active' AND expires_at>now()),count(*),count(*) FILTER (WHERE risk_state='elevated'),count(*) FILTER (WHERE risk_state='compromised') FROM auth_sessions`).Scan(&active, &total, &elevated, &compromised)
	if err != nil {
		return map[string]any{"backend": "postgres-session-management-2.0", "status": "unavailable", "error": err.Error()}
	}
	return map[string]any{"active": active, "revokedOrExpired": total - active, "total": total, "backend": "postgres-session-management-2.0", "sourceOfTruth": "PostgreSQL", "reuseDetection": "refresh-token-family", "risk": map[string]int{"elevated": elevated, "compromised": compromised}}
}

func sortSessions118(items []authSessionRecord) {
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeenAt.After(items[j].LastSeenAt) })
}

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func normalizeTrustedDevice0121(device model.TrustedDevice) (model.TrustedDevice, error) {
	device.ID = strings.TrimSpace(device.ID)
	device.UserID = strings.TrimSpace(device.UserID)
	device.Name = strings.TrimSpace(device.Name)
	device.Status = strings.ToLower(strings.TrimSpace(device.Status))
	device.TrustState = strings.ToLower(strings.TrimSpace(device.TrustState))
	device.Assurance = strings.ToLower(strings.TrimSpace(device.Assurance))
	device.KeyAlgorithm = strings.ToLower(strings.TrimSpace(device.KeyAlgorithm))
	device.PublicKey = strings.TrimSpace(device.PublicKey)
	device.KeyFingerprint = strings.ToLower(strings.TrimSpace(device.KeyFingerprint))
	device.Platform = strings.TrimSpace(device.Platform)
	device.ClientVersion = strings.TrimSpace(device.ClientVersion)
	if device.ID == "" || device.UserID == "" || device.Name == "" || device.PublicKey == "" || device.KeyFingerprint == "" {
		return model.TrustedDevice{}, errors.New("device id, user id, name, public key and fingerprint are required")
	}
	if device.Status == "" {
		device.Status = "active"
	}
	if device.TrustState == "" {
		device.TrustState = "verified"
	}
	if device.Assurance == "" {
		device.Assurance = "proof-of-possession"
	}
	if device.KeyAlgorithm == "" {
		device.KeyAlgorithm = "ed25519"
	}
	if device.Status != "active" && device.Status != "revoked" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device status %q", device.Status)
	}
	if device.TrustState != "verified" && device.TrustState != "revoked" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported trust state %q", device.TrustState)
	}
	if device.KeyAlgorithm != "ed25519" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device key algorithm %q", device.KeyAlgorithm)
	}
	return device, nil
}

func cloneDeviceChallenge0121(ch model.DeviceChallenge) model.DeviceChallenge {
	out := ch
	if ch.Metadata != nil {
		out.Metadata = make(map[string]any, len(ch.Metadata))
		for k, v := range ch.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}

func (r *MemoryRepository) SaveTrustedDevice(ctx context.Context, device model.TrustedDevice) (model.TrustedDevice, error) {
	_ = ctx
	var err error
	device, err = normalizeTrustedDevice0121(device)
	if err != nil {
		return model.TrustedDevice{}, err
	}
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for _, existing := range r.trustedDevices {
		if existing.KeyFingerprint == device.KeyFingerprint && existing.ID != device.ID {
			return model.TrustedDevice{}, fmt.Errorf("%w: device key fingerprint is already registered", ErrConflict)
		}
	}
	now := time.Now().UTC()
	if device.CreatedAt.IsZero() {
		device.CreatedAt = now
	}
	device.UpdatedAt = now
	for i, existing := range r.trustedDevices {
		if existing.ID != device.ID {
			continue
		}
		if existing.UserID != device.UserID {
			return model.TrustedDevice{}, fmt.Errorf("%w: device id is already owned by another user", ErrConflict)
		}
		device.CreatedAt = existing.CreatedAt
		r.trustedDevices[i] = device
		return device, nil
	}
	r.trustedDevices = append(r.trustedDevices, device)
	return device, nil
}

func (r *MemoryRepository) GetTrustedDevice(userID, deviceID string) (model.TrustedDevice, error) {
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for _, item := range r.trustedDevices {
		if item.ID == strings.TrimSpace(deviceID) && item.UserID == strings.TrimSpace(userID) {
			return item, nil
		}
	}
	return model.TrustedDevice{}, ErrNotFound
}

func (r *MemoryRepository) GetTrustedDeviceByID(deviceID string) (model.TrustedDevice, error) {
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for _, item := range r.trustedDevices {
		if item.ID == strings.TrimSpace(deviceID) {
			return item, nil
		}
	}
	return model.TrustedDevice{}, ErrNotFound
}

func (r *MemoryRepository) ListTrustedDevices(userID, status string) []model.TrustedDevice {
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	userID = strings.TrimSpace(userID)
	status = strings.ToLower(strings.TrimSpace(status))
	out := make([]model.TrustedDevice, 0)
	for _, item := range r.trustedDevices {
		if userID != "" && item.UserID != userID {
			continue
		}
		if status != "" && item.Status != status {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

func (r *MemoryRepository) RenameTrustedDevice(userID, deviceID, name string) (model.TrustedDevice, error) {
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	name = strings.TrimSpace(name)
	for i, item := range r.trustedDevices {
		if item.ID == strings.TrimSpace(deviceID) && item.UserID == strings.TrimSpace(userID) {
			item.Name = name
			item.UpdatedAt = time.Now().UTC()
			r.trustedDevices[i] = item
			return item, nil
		}
	}
	return model.TrustedDevice{}, ErrNotFound
}

func (r *MemoryRepository) RevokeTrustedDevice(ctx context.Context, userID, deviceID, reason string) (model.TrustedDevice, error) {
	_ = ctx
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for i, item := range r.trustedDevices {
		if item.ID != strings.TrimSpace(deviceID) || (strings.TrimSpace(userID) != "" && item.UserID != strings.TrimSpace(userID)) {
			continue
		}
		if item.Status != "revoked" {
			now := time.Now().UTC()
			item.Status = "revoked"
			item.TrustState = "revoked"
			item.RevokedAt = now
			item.RevokedReason = strings.TrimSpace(reason)
			item.UpdatedAt = now
			r.trustedDevices[i] = item
		}
		return item, nil
	}
	return model.TrustedDevice{}, ErrNotFound
}

func (r *MemoryRepository) TouchTrustedDevice(ctx context.Context, userID, deviceID, ip, userAgent string) (model.TrustedDevice, error) {
	_ = ctx
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for i, item := range r.trustedDevices {
		if item.ID == strings.TrimSpace(deviceID) && item.UserID == strings.TrimSpace(userID) && item.Status == "active" {
			now := time.Now().UTC()
			item.LastSeenAt = now
			item.LastVerifiedAt = now
			item.LastIP = strings.TrimSpace(ip)
			item.LastUserAgent = strings.TrimSpace(userAgent)
			item.UpdatedAt = now
			r.trustedDevices[i] = item
			return item, nil
		}
	}
	return model.TrustedDevice{}, ErrNotFound
}

func (r *MemoryRepository) SaveDeviceChallenge(ctx context.Context, challenge model.DeviceChallenge) error {
	_ = ctx
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	kept := r.deviceChallenges[:0]
	for _, existing := range r.deviceChallenges {
		if existing.ID == challenge.ID {
			return fmt.Errorf("%w: duplicate device challenge", ErrConflict)
		}
		if (!existing.ConsumedAt.IsZero() && existing.ConsumedAt.Before(cutoff)) || existing.ExpiresAt.Before(cutoff) {
			continue
		}
		kept = append(kept, existing)
	}
	r.deviceChallenges = kept
	r.deviceChallenges = append(r.deviceChallenges, cloneDeviceChallenge0121(challenge))
	return nil
}

func (r *MemoryRepository) ConsumeDeviceChallenge(ctx context.Context, id, userID, deviceID, purpose, challengeHash string, now time.Time) (model.DeviceChallenge, error) {
	_ = ctx
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for i, item := range r.deviceChallenges {
		if item.ID != strings.TrimSpace(id) || item.UserID != strings.TrimSpace(userID) || item.DeviceID != strings.TrimSpace(deviceID) || item.Purpose != strings.TrimSpace(purpose) || item.ChallengeHash != strings.TrimSpace(challengeHash) {
			continue
		}
		if !item.ConsumedAt.IsZero() || !item.ExpiresAt.After(now) {
			return model.DeviceChallenge{}, ErrNotFound
		}
		item.ConsumedAt = now
		r.deviceChallenges[i] = item
		return cloneDeviceChallenge0121(item), nil
	}
	return model.DeviceChallenge{}, ErrNotFound
}

const trustedDeviceColumns0121 = `id,user_id,name,status,trust_state,assurance,key_algorithm,public_key,key_fingerprint,platform,client_version,created_at,updated_at,last_seen_at,last_verified_at,last_ip,last_user_agent,revoked_at,revoked_reason`

func scanTrustedDevice0121(row interface{ Scan(...any) error }) (model.TrustedDevice, error) {
	var d model.TrustedDevice
	var lastSeen, lastVerified, revoked sql.NullTime
	err := row.Scan(&d.ID, &d.UserID, &d.Name, &d.Status, &d.TrustState, &d.Assurance, &d.KeyAlgorithm, &d.PublicKey, &d.KeyFingerprint, &d.Platform, &d.ClientVersion, &d.CreatedAt, &d.UpdatedAt, &lastSeen, &lastVerified, &d.LastIP, &d.LastUserAgent, &revoked, &d.RevokedReason)
	if err != nil {
		return model.TrustedDevice{}, err
	}
	if lastSeen.Valid {
		d.LastSeenAt = lastSeen.Time.UTC()
	}
	if lastVerified.Valid {
		d.LastVerifiedAt = lastVerified.Time.UTC()
	}
	if revoked.Valid {
		d.RevokedAt = revoked.Time.UTC()
	}
	return d, nil
}

func (r *SQLRepository) SaveTrustedDevice(ctx context.Context, device model.TrustedDevice) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	var err error
	device, err = normalizeTrustedDevice0121(device)
	if err != nil {
		return model.TrustedDevice{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()
	if device.CreatedAt.IsZero() {
		device.CreatedAt = now
	}
	device.UpdatedAt = now
	res, err := r.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,status,trust_state,assurance,key_algorithm,public_key,key_fingerprint,platform,client_version,created_at,updated_at,last_seen_at,last_verified_at,last_ip,last_user_agent,revoked_at,revoked_reason)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULLIF($14,'0001-01-01T00:00:00Z')::timestamptz,NULLIF($15,'0001-01-01T00:00:00Z')::timestamptz,$16,$17,NULLIF($18,'0001-01-01T00:00:00Z')::timestamptz,$19)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,status=EXCLUDED.status,trust_state=EXCLUDED.trust_state,assurance=EXCLUDED.assurance,key_algorithm=EXCLUDED.key_algorithm,public_key=EXCLUDED.public_key,key_fingerprint=EXCLUDED.key_fingerprint,platform=EXCLUDED.platform,client_version=EXCLUDED.client_version,updated_at=EXCLUDED.updated_at,last_seen_at=EXCLUDED.last_seen_at,last_verified_at=EXCLUDED.last_verified_at,last_ip=EXCLUDED.last_ip,last_user_agent=EXCLUDED.last_user_agent,revoked_at=EXCLUDED.revoked_at,revoked_reason=EXCLUDED.revoked_reason WHERE trusted_devices.user_id=EXCLUDED.user_id`, device.ID, device.UserID, device.Name, device.Status, device.TrustState, device.Assurance, device.KeyAlgorithm, device.PublicKey, device.KeyFingerprint, device.Platform, device.ClientVersion, device.CreatedAt, device.UpdatedAt, device.LastSeenAt.UTC().Format(time.RFC3339), device.LastVerifiedAt.UTC().Format(time.RFC3339), device.LastIP, device.LastUserAgent, device.RevokedAt.UTC().Format(time.RFC3339), device.RevokedReason)
	if err != nil {
		// key_fingerprint is globally unique. Resolve a concurrent or pre-existing
		// registration back to the repository-level conflict contract instead of
		// leaking a driver-specific unique-violation as HTTP 500.
		var existingID, existingUser string
		lookupErr := r.db.QueryRowContext(ctx, `SELECT id,user_id FROM trusted_devices WHERE key_fingerprint=$1`, device.KeyFingerprint).Scan(&existingID, &existingUser)
		if lookupErr == nil {
			return model.TrustedDevice{}, fmt.Errorf("%w: device key fingerprint is already registered", ErrConflict)
		}
		return model.TrustedDevice{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.TrustedDevice{}, fmt.Errorf("%w: trusted device belongs to another user", ErrConflict)
	}
	return r.GetTrustedDevice(device.UserID, device.ID)
}

func (r *SQLRepository) GetTrustedDevice(userID, deviceID string) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := scanTrustedDevice0121(r.db.QueryRowContext(ctx, `SELECT `+trustedDeviceColumns0121+` FROM trusted_devices WHERE id=$1 AND user_id=$2`, strings.TrimSpace(deviceID), strings.TrimSpace(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.TrustedDevice{}, ErrNotFound
	}
	return d, err
}

func (r *SQLRepository) GetTrustedDeviceByID(deviceID string) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := scanTrustedDevice0121(r.db.QueryRowContext(ctx, `SELECT `+trustedDeviceColumns0121+` FROM trusted_devices WHERE id=$1`, strings.TrimSpace(deviceID)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.TrustedDevice{}, ErrNotFound
	}
	return d, err
}

func (r *SQLRepository) ListTrustedDevices(userID, status string) []model.TrustedDevice {
	if err := r.check(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	rows, err := r.db.QueryContext(ctx, `SELECT `+trustedDeviceColumns0121+` FROM trusted_devices WHERE ($1='' OR user_id=$1) AND ($2='' OR status=$2) ORDER BY updated_at DESC LIMIT 1000`, strings.TrimSpace(userID), strings.ToLower(strings.TrimSpace(status)))
	if err != nil {
		return []model.TrustedDevice{}
	}
	defer rows.Close()
	out := []model.TrustedDevice{}
	for rows.Next() {
		if d, err := scanTrustedDevice0121(rows); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func (r *SQLRepository) RenameTrustedDevice(userID, deviceID, name string) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	res, err := r.db.ExecContext(ctx, `UPDATE trusted_devices SET name=$3,updated_at=now() WHERE id=$1 AND user_id=$2`, strings.TrimSpace(deviceID), strings.TrimSpace(userID), strings.TrimSpace(name))
	if err != nil {
		return model.TrustedDevice{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.TrustedDevice{}, ErrNotFound
	}
	return r.GetTrustedDevice(userID, deviceID)
}

func (r *SQLRepository) RevokeTrustedDevice(ctx context.Context, userID, deviceID, reason string) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.TrustedDevice{}, err
	}
	defer tx.Rollback()
	var owner string
	if err := tx.QueryRowContext(ctx, `SELECT user_id FROM trusted_devices WHERE id=$1 FOR UPDATE`, strings.TrimSpace(deviceID)).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.TrustedDevice{}, ErrNotFound
		}
		return model.TrustedDevice{}, err
	}
	if strings.TrimSpace(userID) != "" && owner != strings.TrimSpace(userID) {
		return model.TrustedDevice{}, ErrNotFound
	}
	now := time.Now().UTC()
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "device-revoked"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE trusted_devices SET status='revoked',trust_state='revoked',revoked_at=COALESCE(revoked_at,$2),revoked_reason=CASE WHEN revoked_reason='' THEN $3 ELSE revoked_reason END,updated_at=$2 WHERE id=$1`, deviceID, now, reason); err != nil {
		return model.TrustedDevice{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE trusted_device_id=$1 AND status='active' FOR UPDATE`, deviceID)
	if err != nil {
		return model.TrustedDevice{}, err
	}
	type pair struct{ session, family string }
	affected := []pair{}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.session, &p.family); err != nil {
			rows.Close()
			return model.TrustedDevice{}, err
		}
		affected = append(affected, p)
	}
	rows.Close()
	for _, a := range affected {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3,risk_state='compromised',risk_reasons=risk_reasons || jsonb_build_array($3),risk_updated_at=$2,device_trust_state='revoked' WHERE id=$1`, a.session, now, reason); err != nil {
			return model.TrustedDevice{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1`, a.family, now, reason); err != nil {
			return model.TrustedDevice{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, a.family, now); err != nil {
			return model.TrustedDevice{}, err
		}
		_, _ = tx.ExecContext(ctx, `INSERT INTO auth_events(user_id,session_id,family_id,event_type,details,created_at) VALUES($1,$2,$3,'trusted-device-revoked',jsonb_build_object('deviceId',$4,'reason',$5),$6)`, owner, a.session, a.family, deviceID, reason, now)
	}
	if err := tx.Commit(); err != nil {
		return model.TrustedDevice{}, err
	}
	return r.GetTrustedDevice(owner, deviceID)
}

func (r *SQLRepository) TouchTrustedDevice(ctx context.Context, userID, deviceID, ip, userAgent string) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := r.db.ExecContext(ctx, `UPDATE trusted_devices SET last_seen_at=now(),last_verified_at=now(),last_ip=$3,last_user_agent=$4,updated_at=now() WHERE id=$1 AND user_id=$2 AND status='active'`, strings.TrimSpace(deviceID), strings.TrimSpace(userID), strings.TrimSpace(ip), strings.TrimSpace(userAgent))
	if err != nil {
		return model.TrustedDevice{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.TrustedDevice{}, ErrNotFound
	}
	return r.GetTrustedDevice(userID, deviceID)
}

func (r *SQLRepository) SaveDeviceChallenge(ctx context.Context, challenge model.DeviceChallenge) error {
	if err := r.check(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := json.Marshal(challenge.Metadata)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `DELETE FROM device_challenges WHERE (consumed_at IS NOT NULL AND consumed_at<now()-interval '24 hours') OR expires_at<now()-interval '24 hours'`)
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_challenges(id,user_id,device_id,purpose,challenge_hash,metadata,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, challenge.ID, challenge.UserID, challenge.DeviceID, challenge.Purpose, challenge.ChallengeHash, string(raw), challenge.CreatedAt, challenge.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLRepository) ConsumeDeviceChallenge(ctx context.Context, id, userID, deviceID, purpose, challengeHash string, now time.Time) (model.DeviceChallenge, error) {
	if err := r.check(); err != nil {
		return model.DeviceChallenge{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var ch model.DeviceChallenge
	var raw []byte
	err := r.db.QueryRowContext(ctx, `UPDATE device_challenges SET consumed_at=$6 WHERE id=$1 AND user_id=$2 AND device_id=$3 AND purpose=$4 AND challenge_hash=$5 AND consumed_at IS NULL AND expires_at>$6 RETURNING id,user_id,device_id,purpose,challenge_hash,metadata,created_at,expires_at,consumed_at`, strings.TrimSpace(id), strings.TrimSpace(userID), strings.TrimSpace(deviceID), strings.TrimSpace(purpose), strings.TrimSpace(challengeHash), now).Scan(&ch.ID, &ch.UserID, &ch.DeviceID, &ch.Purpose, &ch.ChallengeHash, &raw, &ch.CreatedAt, &ch.ExpiresAt, &ch.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DeviceChallenge{}, ErrNotFound
	}
	if err != nil {
		return model.DeviceChallenge{}, err
	}
	_ = json.Unmarshal(raw, &ch.Metadata)
	return ch, nil
}

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
	"unicode"
	"unicode/utf8"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func validHardwareProvider0123(provider string) bool {
	if provider == "" || len(provider) > 96 || !utf8.ValidString(provider) {
		return false
	}
	for _, r := range provider {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func normalizeTrustedDevice0121(device model.TrustedDevice) (model.TrustedDevice, error) {
	device.ID = strings.TrimSpace(device.ID)
	device.UserID = strings.TrimSpace(device.UserID)
	device.Name = strings.TrimSpace(device.Name)
	device.Status = strings.ToLower(strings.TrimSpace(device.Status))
	device.TrustState = strings.ToLower(strings.TrimSpace(device.TrustState))
	device.Assurance = strings.ToLower(strings.TrimSpace(device.Assurance))
	device.KeyAlgorithm = strings.ToLower(strings.TrimSpace(device.KeyAlgorithm))
	device.KeyBinding = strings.ToLower(strings.TrimSpace(device.KeyBinding))
	device.HardwareProvider = strings.TrimSpace(device.HardwareProvider)
	device.AttestationState = strings.ToLower(strings.TrimSpace(device.AttestationState))
	device.AttestationMethod = strings.ToLower(strings.TrimSpace(device.AttestationMethod))
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
	if device.KeyBinding == "" {
		device.KeyBinding = "software"
	}
	if device.AttestationState == "" {
		device.AttestationState = "unattested"
	}
	if device.Status != "active" && device.Status != "revoked" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device status %q", device.Status)
	}
	if device.TrustState != "verified" && device.TrustState != "revoked" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported trust state %q", device.TrustState)
	}
	if device.KeyAlgorithm != "ed25519" && device.KeyAlgorithm != "p256" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device key algorithm %q", device.KeyAlgorithm)
	}
	if device.KeyBinding != "software" && device.KeyBinding != "hardware" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device key binding %q", device.KeyBinding)
	}
	if device.Assurance != "proof-of-possession" && device.Assurance != "challenge-response-attested" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device assurance %q", device.Assurance)
	}
	if device.AttestationState != "unattested" && device.AttestationState != "verified" && device.AttestationState != "revoked" {
		return model.TrustedDevice{}, fmt.Errorf("unsupported device attestation state %q", device.AttestationState)
	}
	if device.AttestationState == "verified" {
		if device.AttestationMethod != "challenge-response-v1" || device.AttestedAt.IsZero() || device.AttestationExpiresAt.IsZero() || !device.AttestationExpiresAt.After(device.AttestedAt) {
			return model.TrustedDevice{}, errors.New("verified device attestation requires method and a valid freshness window")
		}
	} else if device.AttestationState == "unattested" {
		device.AttestationMethod = ""
		device.AttestedAt = time.Time{}
		device.AttestationExpiresAt = time.Time{}
		if device.Assurance == "challenge-response-attested" {
			device.Assurance = "proof-of-possession"
		}
	}
	if device.KeyBinding == "hardware" {
		if device.KeyAlgorithm != "p256" {
			return model.TrustedDevice{}, errors.New("hardware-bound device keys must use p256")
		}
		if !validHardwareProvider0123(device.HardwareProvider) {
			return model.TrustedDevice{}, errors.New("hardware-bound device key requires hardware provider")
		}
	} else {
		device.HardwareProvider = ""
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

func (r *MemoryRepository) revokeTrustedDeviceLocked0125(userID, deviceID, reason string, now time.Time) (model.DeviceRevocationResult, error) {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "device-revoked"
	}
	for i, item := range r.trustedDevices {
		if item.ID != deviceID || (userID != "" && item.UserID != userID) {
			continue
		}
		result := model.DeviceRevocationResult{Device: item, AlreadyRevoked: item.Status == "revoked", CascadeHandled: false}
		if !result.AlreadyRevoked {
			item.Status = "revoked"
			item.TrustState = "revoked"
			item.AttestationState = "revoked"
			item.Assurance = "proof-of-possession"
			item.RevokedAt = now
			item.RevokedReason = reason
			item.UpdatedAt = now
			r.trustedDevices[i] = item
			result.Device = item
		}
		for ci, ch := range r.deviceChallenges {
			if ch.DeviceID == deviceID && ch.ConsumedAt.IsZero() {
				ch.ConsumedAt = now
				r.deviceChallenges[ci] = ch
				result.InvalidatedChallenges++
			}
		}
		return result, nil
	}
	return model.DeviceRevocationResult{}, ErrNotFound
}

func (r *MemoryRepository) RevokeTrustedDevice(ctx context.Context, userID, deviceID, reason string) (model.DeviceRevocationResult, error) {
	_ = ctx
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	return r.revokeTrustedDeviceLocked0125(userID, deviceID, reason, time.Now().UTC())
}

func (r *MemoryRepository) RevokeOtherTrustedDevices(ctx context.Context, userID, exceptDeviceID, reason string) (model.DeviceRevocationBatch, error) {
	_ = ctx
	userID = strings.TrimSpace(userID)
	exceptDeviceID = strings.TrimSpace(exceptDeviceID)
	if userID == "" || exceptDeviceID == "" {
		return model.DeviceRevocationBatch{}, errors.New("user id and preserved device id are required")
	}
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	now := time.Now().UTC()
	batch := model.DeviceRevocationBatch{CascadeHandled: false}
	for _, item := range append([]model.TrustedDevice(nil), r.trustedDevices...) {
		if item.UserID != userID || item.ID == exceptDeviceID || item.Status != "active" {
			continue
		}
		result, err := r.revokeTrustedDeviceLocked0125(userID, item.ID, reason, now)
		if err != nil {
			return model.DeviceRevocationBatch{}, err
		}
		batch.Devices = append(batch.Devices, result.Device)
		if result.AlreadyRevoked {
			batch.AlreadyRevoked++
		} else {
			batch.RevokedDevices++
		}
		batch.InvalidatedChallenges += result.InvalidatedChallenges
	}
	return batch, nil
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

func (r *MemoryRepository) AttestTrustedDevice(ctx context.Context, userID, deviceID, method string, attestedAt, expiresAt time.Time) (model.TrustedDevice, error) {
	_ = ctx
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for i, item := range r.trustedDevices {
		if item.ID != strings.TrimSpace(deviceID) || item.UserID != strings.TrimSpace(userID) || item.Status != "active" || item.TrustState != "verified" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(method)) != "challenge-response-v1" || attestedAt.IsZero() || !expiresAt.After(attestedAt) {
			return model.TrustedDevice{}, errors.New("invalid attestation result")
		}
		item.AttestationState = "verified"
		item.AttestationMethod = "challenge-response-v1"
		item.AttestedAt = attestedAt.UTC()
		item.AttestationExpiresAt = expiresAt.UTC()
		item.Assurance = "challenge-response-attested"
		item.LastVerifiedAt = attestedAt.UTC()
		item.UpdatedAt = attestedAt.UTC()
		r.trustedDevices[i] = item
		return item, nil
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

const trustedDeviceColumns0121 = `id,user_id,name,status,trust_state,assurance,key_algorithm,key_binding,hardware_provider,attestation_state,attestation_method,attested_at,attestation_expires_at,public_key,key_fingerprint,platform,client_version,created_at,updated_at,last_seen_at,last_verified_at,last_ip,last_user_agent,revoked_at,revoked_reason,replaced_at,replaced_by_device_id,replacement_reason`

func scanTrustedDevice0121(row interface{ Scan(...any) error }) (model.TrustedDevice, error) {
	var d model.TrustedDevice
	var lastSeen, lastVerified, attested, attestationExpires, revoked, replaced sql.NullTime
	err := row.Scan(&d.ID, &d.UserID, &d.Name, &d.Status, &d.TrustState, &d.Assurance, &d.KeyAlgorithm, &d.KeyBinding, &d.HardwareProvider, &d.AttestationState, &d.AttestationMethod, &attested, &attestationExpires, &d.PublicKey, &d.KeyFingerprint, &d.Platform, &d.ClientVersion, &d.CreatedAt, &d.UpdatedAt, &lastSeen, &lastVerified, &d.LastIP, &d.LastUserAgent, &revoked, &d.RevokedReason, &replaced, &d.ReplacedByDeviceID, &d.ReplacementReason)
	if err != nil {
		return model.TrustedDevice{}, err
	}
	if attested.Valid {
		d.AttestedAt = attested.Time.UTC()
	}
	if attestationExpires.Valid {
		d.AttestationExpiresAt = attestationExpires.Time.UTC()
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
	if replaced.Valid {
		d.ReplacedAt = replaced.Time.UTC()
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
	res, err := r.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,status,trust_state,assurance,key_algorithm,key_binding,hardware_provider,attestation_state,attestation_method,attested_at,attestation_expires_at,public_key,key_fingerprint,platform,client_version,created_at,updated_at,last_seen_at,last_verified_at,last_ip,last_user_agent,revoked_at,revoked_reason)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,'0001-01-01T00:00:00Z')::timestamptz,NULLIF($13,'0001-01-01T00:00:00Z')::timestamptz,$14,$15,$16,$17,$18,$19,NULLIF($20,'0001-01-01T00:00:00Z')::timestamptz,NULLIF($21,'0001-01-01T00:00:00Z')::timestamptz,$22,$23,NULLIF($24,'0001-01-01T00:00:00Z')::timestamptz,$25)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,status=EXCLUDED.status,trust_state=EXCLUDED.trust_state,assurance=EXCLUDED.assurance,key_algorithm=EXCLUDED.key_algorithm,key_binding=EXCLUDED.key_binding,hardware_provider=EXCLUDED.hardware_provider,attestation_state=EXCLUDED.attestation_state,attestation_method=EXCLUDED.attestation_method,attested_at=EXCLUDED.attested_at,attestation_expires_at=EXCLUDED.attestation_expires_at,public_key=EXCLUDED.public_key,key_fingerprint=EXCLUDED.key_fingerprint,platform=EXCLUDED.platform,client_version=EXCLUDED.client_version,updated_at=EXCLUDED.updated_at,last_seen_at=EXCLUDED.last_seen_at,last_verified_at=EXCLUDED.last_verified_at,last_ip=EXCLUDED.last_ip,last_user_agent=EXCLUDED.last_user_agent,revoked_at=EXCLUDED.revoked_at,revoked_reason=EXCLUDED.revoked_reason WHERE trusted_devices.user_id=EXCLUDED.user_id`, device.ID, device.UserID, device.Name, device.Status, device.TrustState, device.Assurance, device.KeyAlgorithm, device.KeyBinding, device.HardwareProvider, device.AttestationState, device.AttestationMethod, device.AttestedAt.UTC().Format(time.RFC3339), device.AttestationExpiresAt.UTC().Format(time.RFC3339), device.PublicKey, device.KeyFingerprint, device.Platform, device.ClientVersion, device.CreatedAt, device.UpdatedAt, device.LastSeenAt.UTC().Format(time.RFC3339), device.LastVerifiedAt.UTC().Format(time.RFC3339), device.LastIP, device.LastUserAgent, device.RevokedAt.UTC().Format(time.RFC3339), device.RevokedReason)
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

func revokeTrustedDeviceSQLTx0125(ctx context.Context, tx *sql.Tx, userID, deviceID, reason string, now time.Time) (model.DeviceRevocationResult, error) {
	deviceID = strings.TrimSpace(deviceID)
	userID = strings.TrimSpace(userID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "device-revoked"
	}
	var owner, status string
	if err := tx.QueryRowContext(ctx, `SELECT user_id,status FROM trusted_devices WHERE id=$1 FOR UPDATE`, deviceID).Scan(&owner, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.DeviceRevocationResult{}, ErrNotFound
		}
		return model.DeviceRevocationResult{}, err
	}
	if userID != "" && owner != userID {
		return model.DeviceRevocationResult{}, ErrNotFound
	}
	result := model.DeviceRevocationResult{AlreadyRevoked: status == "revoked", CascadeHandled: true}
	if !result.AlreadyRevoked {
		if _, err := tx.ExecContext(ctx, `UPDATE trusted_devices SET status='revoked',trust_state='revoked',assurance='proof-of-possession',attestation_state='revoked',revoked_at=$2,revoked_reason=$3,updated_at=$2 WHERE id=$1`, deviceID, now, reason); err != nil {
			return model.DeviceRevocationResult{}, err
		}
	}
	if res, err := tx.ExecContext(ctx, `UPDATE device_challenges SET consumed_at=$2 WHERE device_id=$1 AND consumed_at IS NULL`, deviceID, now); err != nil {
		return model.DeviceRevocationResult{}, err
	} else if n, err := res.RowsAffected(); err == nil {
		result.InvalidatedChallenges = int(n)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE user_id=$1 AND trusted_device_id=$2 AND status='active' FOR UPDATE`, owner, deviceID)
	if err != nil {
		return model.DeviceRevocationResult{}, err
	}
	type pair struct{ session, family string }
	affected := []pair{}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.session, &p.family); err != nil {
			rows.Close()
			return model.DeviceRevocationResult{}, err
		}
		affected = append(affected, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return model.DeviceRevocationResult{}, err
	}
	rows.Close()
	families := map[string]struct{}{}
	for _, a := range affected {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3,risk_state='compromised',risk_reasons=risk_reasons || jsonb_build_array($3),risk_score=100,risk_action='revoke',risk_evaluated_at=$2,risk_updated_at=$2,device_trust_state='revoked' WHERE id=$1 AND status='active'`, a.session, now, reason); err != nil {
			return model.DeviceRevocationResult{}, err
		}
		if a.family != "" {
			families[a.family] = struct{}{}
			if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1 AND status<>'revoked'`, a.family, now, reason); err != nil {
				return model.DeviceRevocationResult{}, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, a.family, now); err != nil {
				return model.DeviceRevocationResult{}, err
			}
		}
		if res, err := tx.ExecContext(ctx, `UPDATE minecraft_sessions SET status='revoked',revoked_at=COALESCE(revoked_at,$2),revoked_reason=CASE WHEN revoked_reason='' THEN $3 ELSE revoked_reason END WHERE never_session_id=$1 AND status='active'`, a.session, now, reason); err != nil {
			return model.DeviceRevocationResult{}, err
		} else if n, err := res.RowsAffected(); err == nil {
			result.RevokedMinecraftSessions += int(n)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_events(user_id,session_id,family_id,event_type,details,created_at) VALUES($1,$2,$3,'trusted-device-revoked',jsonb_build_object('deviceId',$4,'reason',$5),$6)`, owner, a.session, a.family, deviceID, reason, now); err != nil {
			return model.DeviceRevocationResult{}, err
		}
		result.RevokedSessionIDs = append(result.RevokedSessionIDs, a.session)
	}
	result.RevokedSessions = len(affected)
	result.RevokedRefreshFamilies = len(families)
	return result, nil
}

func (r *SQLRepository) RevokeTrustedDevice(ctx context.Context, userID, deviceID, reason string) (model.DeviceRevocationResult, error) {
	if err := r.check(); err != nil {
		return model.DeviceRevocationResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DeviceRevocationResult{}, err
	}
	defer tx.Rollback()
	result, err := revokeTrustedDeviceSQLTx0125(ctx, tx, userID, deviceID, reason, time.Now().UTC())
	if err != nil {
		return model.DeviceRevocationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.DeviceRevocationResult{}, err
	}
	owner := strings.TrimSpace(userID)
	if owner == "" {
		device, err := r.GetTrustedDeviceByID(deviceID)
		if err != nil {
			return model.DeviceRevocationResult{}, err
		}
		result.Device = device
	} else {
		device, err := r.GetTrustedDevice(owner, deviceID)
		if err != nil {
			return model.DeviceRevocationResult{}, err
		}
		result.Device = device
	}
	return result, nil
}

func (r *SQLRepository) RevokeOtherTrustedDevices(ctx context.Context, userID, exceptDeviceID, reason string) (model.DeviceRevocationBatch, error) {
	if err := r.check(); err != nil {
		return model.DeviceRevocationBatch{}, err
	}
	userID = strings.TrimSpace(userID)
	exceptDeviceID = strings.TrimSpace(exceptDeviceID)
	if userID == "" || exceptDeviceID == "" {
		return model.DeviceRevocationBatch{}, errors.New("user id and preserved device id are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DeviceRevocationBatch{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM trusted_devices WHERE user_id=$1 AND id<>$2 AND status='active' ORDER BY id FOR UPDATE`, userID, exceptDeviceID)
	if err != nil {
		return model.DeviceRevocationBatch{}, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return model.DeviceRevocationBatch{}, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return model.DeviceRevocationBatch{}, err
	}
	rows.Close()
	batch := model.DeviceRevocationBatch{CascadeHandled: true}
	now := time.Now().UTC()
	for _, id := range ids {
		result, err := revokeTrustedDeviceSQLTx0125(ctx, tx, userID, id, reason, now)
		if err != nil {
			return model.DeviceRevocationBatch{}, err
		}
		if result.AlreadyRevoked {
			batch.AlreadyRevoked++
		} else {
			batch.RevokedDevices++
		}
		batch.RevokedSessions += result.RevokedSessions
		batch.RevokedRefreshFamilies += result.RevokedRefreshFamilies
		batch.RevokedMinecraftSessions += result.RevokedMinecraftSessions
		batch.InvalidatedChallenges += result.InvalidatedChallenges
		batch.RevokedSessionIDs = append(batch.RevokedSessionIDs, result.RevokedSessionIDs...)
	}
	if err := tx.Commit(); err != nil {
		return model.DeviceRevocationBatch{}, err
	}
	for _, id := range ids {
		if device, err := r.GetTrustedDevice(userID, id); err == nil {
			batch.Devices = append(batch.Devices, device)
		}
	}
	return batch, nil
}

func (r *SQLRepository) ReplaceTrustedDeviceKey(ctx context.Context, userID, oldDeviceID, currentSessionID, mode, reason string, replacement model.TrustedDevice, now time.Time) (model.DeviceKeyReplacementResult, error) {
	if err := r.check(); err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	userID = strings.TrimSpace(userID)
	oldDeviceID = strings.TrimSpace(oldDeviceID)
	currentSessionID = strings.TrimSpace(currentSessionID)
	mode = strings.ToLower(strings.TrimSpace(mode))
	reason = strings.TrimSpace(reason)
	if userID == "" || oldDeviceID == "" || currentSessionID == "" || (mode != "rotate" && mode != "recover") {
		return model.DeviceKeyReplacementResult{}, errors.New("invalid trusted-device replacement request")
	}
	if reason == "" {
		reason = "device-key-" + mode
	}
	var err error
	replacement, err = normalizeTrustedDevice0121(replacement)
	if err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	if replacement.UserID != userID || replacement.ID == oldDeviceID || replacement.Status != "active" || replacement.TrustState != "verified" {
		return model.DeviceKeyReplacementResult{}, errors.New("invalid replacement trusted device")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	defer tx.Rollback()

	var sessionUser, sessionStatus, sessionTrustedDevice, familyID string
	if err := tx.QueryRowContext(ctx, `SELECT user_id,status,COALESCE(trusted_device_id,''),refresh_family_id FROM auth_sessions WHERE id=$1 FOR UPDATE`, currentSessionID).Scan(&sessionUser, &sessionStatus, &sessionTrustedDevice, &familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.DeviceKeyReplacementResult{}, ErrNotFound
		}
		return model.DeviceKeyReplacementResult{}, err
	}
	if sessionUser != userID || sessionStatus != "active" {
		return model.DeviceKeyReplacementResult{}, ErrNotFound
	}
	if mode == "rotate" && sessionTrustedDevice != oldDeviceID {
		return model.DeviceKeyReplacementResult{}, fmt.Errorf("%w: rotation session is not bound to old device", ErrConflict)
	}

	var oldOwner, oldStatus string
	if err := tx.QueryRowContext(ctx, `SELECT user_id,status FROM trusted_devices WHERE id=$1 FOR UPDATE`, oldDeviceID).Scan(&oldOwner, &oldStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.DeviceKeyReplacementResult{}, ErrNotFound
		}
		return model.DeviceKeyReplacementResult{}, err
	}
	if oldOwner != userID || oldStatus != "active" {
		return model.DeviceKeyReplacementResult{}, fmt.Errorf("%w: old trusted device is not active", ErrConflict)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,status,trust_state,assurance,key_algorithm,key_binding,hardware_provider,attestation_state,attestation_method,attested_at,attestation_expires_at,public_key,key_fingerprint,platform,client_version,created_at,updated_at,last_seen_at,last_verified_at,last_ip,last_user_agent,revoked_at,revoked_reason,replaced_at,replaced_by_device_id,replacement_reason)
VALUES($1,$2,$3,'active','verified','proof-of-possession',$4,$5,$6,'unattested','',NULL,NULL,$7,$8,$9,$10,$11,$11,$11,$11,$12,$13,NULL,'',NULL,'','')`, replacement.ID, replacement.UserID, replacement.Name, replacement.KeyAlgorithm, replacement.KeyBinding, replacement.HardwareProvider, replacement.PublicKey, replacement.KeyFingerprint, replacement.Platform, replacement.ClientVersion, now, replacement.LastIP, replacement.LastUserAgent)
	if err != nil {
		var existingID string
		if lookupErr := tx.QueryRowContext(ctx, `SELECT id FROM trusted_devices WHERE key_fingerprint=$1`, replacement.KeyFingerprint).Scan(&existingID); lookupErr == nil {
			return model.DeviceKeyReplacementResult{}, fmt.Errorf("%w: replacement fingerprint already registered", ErrConflict)
		}
		return model.DeviceKeyReplacementResult{}, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET trusted_device_id=$3,device_trust_state='verified',device_verified_at=$4,binding_epoch=GREATEST(binding_epoch,1)+1,last_seen_at=$4,risk_state='normal',risk_reasons='[]'::jsonb,risk_score=0,risk_action='allow',risk_evaluated_at=$4,risk_updated_at=NULL WHERE id=$1 AND user_id=$2 AND status='active'`, currentSessionID, userID, replacement.ID, now); err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE trusted_devices SET status='revoked',trust_state='revoked',assurance='proof-of-possession',attestation_state='revoked',revoked_at=$2,revoked_reason=$3,replaced_at=$2,replaced_by_device_id=$4,replacement_reason=$5,updated_at=$2 WHERE id=$1`, oldDeviceID, now, reason, replacement.ID, mode); err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	result := model.DeviceKeyReplacementResult{}
	if res, err := tx.ExecContext(ctx, `UPDATE device_challenges SET consumed_at=$2 WHERE device_id=$1 AND consumed_at IS NULL`, oldDeviceID, now); err != nil {
		return result, err
	} else if n, e := res.RowsAffected(); e == nil {
		result.InvalidatedChallenges = int(n)
	}

	rows, err := tx.QueryContext(ctx, `SELECT id,refresh_family_id FROM auth_sessions WHERE user_id=$1 AND trusted_device_id=$2 AND status='active' AND id<>$3 FOR UPDATE`, userID, oldDeviceID, currentSessionID)
	if err != nil {
		return result, err
	}
	type pair struct{ session, family string }
	affected := []pair{}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.session, &p.family); err != nil {
			rows.Close()
			return result, err
		}
		affected = append(affected, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	families := map[string]struct{}{}
	for _, a := range affected {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason=$3,risk_state='compromised',risk_reasons=risk_reasons || jsonb_build_array($3),risk_score=100,risk_action='revoke',risk_evaluated_at=$2,risk_updated_at=$2,device_trust_state='revoked' WHERE id=$1 AND status='active'`, a.session, now, reason); err != nil {
			return result, err
		}
		if a.family != "" {
			families[a.family] = struct{}{}
			if _, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET status='revoked',revoked_at=$2,revoked_reason=$3 WHERE id=$1 AND status<>'revoked'`, a.family, now, reason); err != nil {
				return result, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked',revoked_at=$2 WHERE family_id=$1 AND status<>'revoked'`, a.family, now); err != nil {
				return result, err
			}
		}
		if res, err := tx.ExecContext(ctx, `UPDATE minecraft_sessions SET status='revoked',revoked_at=COALESCE(revoked_at,$2),revoked_reason=CASE WHEN revoked_reason='' THEN $3 ELSE revoked_reason END WHERE never_session_id=$1 AND status='active'`, a.session, now, reason); err != nil {
			return result, err
		} else if n, e := res.RowsAffected(); e == nil {
			result.RevokedMinecraftSessions += int(n)
		}
		result.RevokedSessionIDs = append(result.RevokedSessionIDs, a.session)
	}
	// Current gameplay credentials were minted for the old binding epoch and are
	// explicitly revoked rather than left as stale rows that only fail live checks.
	if res, err := tx.ExecContext(ctx, `UPDATE minecraft_sessions SET status='revoked',revoked_at=COALESCE(revoked_at,$2),revoked_reason=CASE WHEN revoked_reason='' THEN $3 ELSE revoked_reason END WHERE never_session_id=$1 AND status='active'`, currentSessionID, now, reason); err != nil {
		return result, err
	} else if n, e := res.RowsAffected(); e == nil {
		result.RevokedMinecraftSessions += int(n)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_events(user_id,session_id,family_id,event_type,details,created_at) VALUES($1,$2,$3,'trusted-device-key-replaced',jsonb_build_object('oldDeviceId',$4,'newDeviceId',$5,'mode',$6),$7)`, userID, currentSessionID, familyID, oldDeviceID, replacement.ID, mode, now); err != nil {
		return result, err
	}
	result.RevokedSessions = len(affected)
	result.RevokedRefreshFamilies = len(families)
	if err := tx.Commit(); err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	result.OldDevice, err = r.GetTrustedDevice(userID, oldDeviceID)
	if err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	result.NewDevice, err = r.GetTrustedDevice(userID, replacement.ID)
	if err != nil {
		return model.DeviceKeyReplacementResult{}, err
	}
	return result, nil
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

func (r *SQLRepository) AttestTrustedDevice(ctx context.Context, userID, deviceID, method string, attestedAt, expiresAt time.Time) (model.TrustedDevice, error) {
	if err := r.check(); err != nil {
		return model.TrustedDevice{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	method = strings.ToLower(strings.TrimSpace(method))
	if method != "challenge-response-v1" || attestedAt.IsZero() || !expiresAt.After(attestedAt) {
		return model.TrustedDevice{}, errors.New("invalid attestation result")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE trusted_devices SET attestation_state='verified',attestation_method=$3,attested_at=$4,attestation_expires_at=$5,assurance='challenge-response-attested',last_verified_at=$4,updated_at=$4 WHERE id=$1 AND user_id=$2 AND status='active' AND trust_state='verified'`, strings.TrimSpace(deviceID), strings.TrimSpace(userID), method, attestedAt.UTC(), expiresAt.UTC())
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

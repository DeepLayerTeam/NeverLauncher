package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// HWID data is deliberately a *risk observation*, never an identity, ban,
// permission, device-key attestation or proof of hardware ownership. Only a
// keyed, account-scoped digest is stored. These structs must not be sent to UI.
type HWIDObservation0299 struct {
	UserID, DeviceID, Baseline, Pending, State string
	UpdatedAt, ExpiresAt                       time.Time
}
type HWIDAppeal0299 struct {
	ID, UserID, DeviceID, Reason, Status, Resolution, Actor, Pending string
	CreatedAt, UpdatedAt                                             time.Time
}
type HWIDStore0299 interface {
	ObserveHWID0299(context.Context, string, string, string, time.Time) (HWIDObservation0299, error)
	GetHWID0299(context.Context, string, string, time.Time) (HWIDObservation0299, error)
	ConfirmHWID0299(context.Context, string, string, time.Time) (HWIDObservation0299, error)
	ForgetHWID0299(context.Context, string, string) error
	SubmitHWIDAppeal0299(context.Context, HWIDAppeal0299) error
	ListHWIDAppeals0299(context.Context, string) ([]HWIDAppeal0299, error)
	ResolveHWIDAppeal0299(context.Context, string, string, string, time.Time) (HWIDAppeal0299, error)
}

const hwidRetention0299 = 30 * 24 * time.Hour

func (r *SQLRepository) ObserveHWID0299(ctx context.Context, userID, deviceID, digest string, now time.Time) (HWIDObservation0299, error) {
	if err := r.check(); err != nil {
		return HWIDObservation0299{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	defer tx.Rollback()
	// The device lock serializes observation/confirmation/forget and prevents
	// cross-user data injection even when a caller bypasses HTTP validation.
	var owner, status string
	err = tx.QueryRowContext(ctx, `SELECT user_id,status FROM trusted_devices WHERE id=$1 FOR UPDATE`, deviceID).Scan(&owner, &status)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	if owner != userID || status != "active" {
		return HWIDObservation0299{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM hwid_risk_observations WHERE user_id=$1 AND device_id=$2 AND expires_at<=$3`, userID, deviceID, now)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	var old string
	err = tx.QueryRowContext(ctx, `SELECT baseline_digest FROM hwid_risk_observations WHERE user_id=$1 AND device_id=$2 FOR UPDATE`, userID, deviceID).Scan(&old)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return HWIDObservation0299{}, err
	}
	obs := HWIDObservation0299{UserID: userID, DeviceID: deviceID, Baseline: old, UpdatedAt: now, ExpiresAt: now.Add(hwidRetention0299)}
	if old == "" {
		obs.Baseline = digest
		obs.State = "recognized"
	} else if old == digest {
		obs.State = "recognized"
	} else {
		obs.Pending = digest
		obs.State = "changed"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO hwid_risk_observations(user_id,device_id,baseline_digest,pending_digest,state,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(user_id,device_id) DO UPDATE SET pending_digest=EXCLUDED.pending_digest,state=EXCLUDED.state,updated_at=EXCLUDED.updated_at,expires_at=EXCLUDED.expires_at`, userID, deviceID, obs.Baseline, obs.Pending, obs.State, now, obs.ExpiresAt)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	return obs, tx.Commit()
}
func (r *SQLRepository) GetHWID0299(ctx context.Context, userID, deviceID string, now time.Time) (HWIDObservation0299, error) {
	if err := r.check(); err != nil {
		return HWIDObservation0299{}, err
	}
	var v HWIDObservation0299
	err := r.db.QueryRowContext(ctx, `SELECT user_id,device_id,baseline_digest,pending_digest,state,updated_at,expires_at FROM hwid_risk_observations WHERE user_id=$1 AND device_id=$2 AND expires_at>$3`, userID, deviceID, now).Scan(&v.UserID, &v.DeviceID, &v.Baseline, &v.Pending, &v.State, &v.UpdatedAt, &v.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return HWIDObservation0299{}, ErrNotFound
	}
	return v, err
}
func (r *SQLRepository) ConfirmHWID0299(ctx context.Context, userID, deviceID string, now time.Time) (HWIDObservation0299, error) {
	if err := r.check(); err != nil {
		return HWIDObservation0299{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	defer tx.Rollback()
	var owner, status string
	if err = tx.QueryRowContext(ctx, `SELECT user_id,status FROM trusted_devices WHERE id=$1 FOR UPDATE`, deviceID).Scan(&owner, &status); err != nil {
		return HWIDObservation0299{}, err
	}
	if owner != userID || status != "active" {
		return HWIDObservation0299{}, ErrConflict
	}
	var v HWIDObservation0299
	err = tx.QueryRowContext(ctx, `UPDATE hwid_risk_observations SET baseline_digest=pending_digest,pending_digest='',state='recognized',updated_at=$3,expires_at=$4 WHERE user_id=$1 AND device_id=$2 AND state='changed' AND pending_digest<>'' AND expires_at>$3 RETURNING user_id,device_id,baseline_digest,pending_digest,state,updated_at,expires_at`, userID, deviceID, now, now.Add(hwidRetention0299)).Scan(&v.UserID, &v.DeviceID, &v.Baseline, &v.Pending, &v.State, &v.UpdatedAt, &v.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return HWIDObservation0299{}, ErrNotFound
	}
	if err != nil {
		return HWIDObservation0299{}, err
	}
	return v, tx.Commit()
}
func (r *SQLRepository) ForgetHWID0299(ctx context.Context, userID, deviceID string) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner string
	if err = tx.QueryRowContext(ctx, `SELECT user_id FROM trusted_devices WHERE id=$1 FOR UPDATE`, deviceID).Scan(&owner); err != nil {
		return err
	}
	if owner != userID {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM hwid_risk_appeals WHERE user_id=$1 AND device_id=$2`, userID, deviceID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM hwid_risk_observations WHERE user_id=$1 AND device_id=$2`, userID, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *SQLRepository) SubmitHWIDAppeal0299(ctx context.Context, a HWIDAppeal0299) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, pending string
	err = tx.QueryRowContext(ctx, `SELECT state,pending_digest FROM hwid_risk_observations WHERE user_id=$1 AND device_id=$2 AND expires_at>now() FOR UPDATE`, a.UserID, a.DeviceID).Scan(&state, &pending)
	if err != nil {
		return err
	}
	if state != "changed" || pending == "" {
		return ErrConflict
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT id FROM hwid_risk_appeals WHERE user_id=$1 AND device_id=$2 AND status='pending'`, a.UserID, a.DeviceID).Scan(&existing)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO hwid_risk_appeals(id,user_id,device_id,pending_digest,reason,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'pending',$6,$6)`, a.ID, a.UserID, a.DeviceID, pending, a.Reason, a.CreatedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func scanAppeal0299(row interface{ Scan(...any) error }) (HWIDAppeal0299, error) {
	var a HWIDAppeal0299
	err := row.Scan(&a.ID, &a.UserID, &a.DeviceID, &a.Reason, &a.Status, &a.Resolution, &a.Actor, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}
func (r *SQLRepository) ListHWIDAppeals0299(ctx context.Context, userID string) ([]HWIDAppeal0299, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	q := `SELECT id,user_id,device_id,reason,status,resolution,actor,created_at,updated_at FROM hwid_risk_appeals`
	args := []any{}
	if userID != "" {
		q += ` WHERE user_id=$1`
		args = append(args, userID)
	}
	q += ` ORDER BY created_at DESC LIMIT 200`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HWIDAppeal0299{}
	for rows.Next() {
		a, err := scanAppeal0299(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (r *SQLRepository) ResolveHWIDAppeal0299(ctx context.Context, id, actor, decision string, now time.Time) (HWIDAppeal0299, error) {
	if err := r.check(); err != nil {
		return HWIDAppeal0299{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return HWIDAppeal0299{}, err
	}
	defer tx.Rollback()
	// Lock device first in the same order as Observe to prevent approve-vs-new-observation races.
	var userID, deviceID string
	err = tx.QueryRowContext(ctx, `SELECT user_id,device_id FROM hwid_risk_appeals WHERE id=$1`, id).Scan(&userID, &deviceID)
	if err != nil {
		return HWIDAppeal0299{}, err
	}
	var owner string
	if err = tx.QueryRowContext(ctx, `SELECT user_id FROM trusted_devices WHERE id=$1 FOR UPDATE`, deviceID).Scan(&owner); err != nil {
		return HWIDAppeal0299{}, err
	}
	if owner != userID {
		return HWIDAppeal0299{}, ErrConflict
	}
	var pending, status string
	err = tx.QueryRowContext(ctx, `SELECT pending_digest,status FROM hwid_risk_appeals WHERE id=$1 FOR UPDATE`, id).Scan(&pending, &status)
	if err != nil {
		return HWIDAppeal0299{}, err
	}
	if status != "pending" {
		return HWIDAppeal0299{}, ErrConflict
	}
	if decision == "approved" {
		result, err := tx.ExecContext(ctx, `UPDATE hwid_risk_observations SET baseline_digest=pending_digest,pending_digest='',state='recognized',updated_at=$4,expires_at=$5 WHERE user_id=$1 AND device_id=$2 AND pending_digest=$3 AND state='changed' AND expires_at>$4`, userID, deviceID, pending, now, now.Add(hwidRetention0299))
		if err != nil {
			return HWIDAppeal0299{}, err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return HWIDAppeal0299{}, ErrConflict
		}
	}
	a, err := scanAppeal0299(tx.QueryRowContext(ctx, `UPDATE hwid_risk_appeals SET status=$2,resolution=$2,actor=$3,updated_at=$4 WHERE id=$1 RETURNING id,user_id,device_id,reason,status,resolution,actor,created_at,updated_at`, id, decision, actor, now))
	if err != nil {
		return HWIDAppeal0299{}, err
	}
	return a, tx.Commit()
}

func (r *MemoryRepository) ObserveHWID0299(_ context.Context, userID, deviceID, digest string, now time.Time) (HWIDObservation0299, error) {
	d, err := r.GetTrustedDevice(userID, deviceID)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	if d.Status != "active" {
		return HWIDObservation0299{}, ErrConflict
	}
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	if r.hwidObservations == nil {
		r.hwidObservations = map[string]HWIDObservation0299{}
	}
	key := userID + "\x00" + deviceID
	old, ok := r.hwidObservations[key]
	if !ok || !old.ExpiresAt.After(now) {
		old = HWIDObservation0299{UserID: userID, DeviceID: deviceID}
	}
	if old.Baseline == "" {
		old.Baseline = digest
		old.Pending = ""
		old.State = "recognized"
	} else if old.Baseline == digest {
		old.Pending = ""
		old.State = "recognized"
	} else {
		old.Pending = digest
		old.State = "changed"
	}
	old.UpdatedAt = now
	old.ExpiresAt = now.Add(hwidRetention0299)
	r.hwidObservations[key] = old
	return old, nil
}
func (r *MemoryRepository) GetHWID0299(_ context.Context, userID, deviceID string, now time.Time) (HWIDObservation0299, error) {
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	v, ok := r.hwidObservations[userID+"\x00"+deviceID]
	if !ok || !v.ExpiresAt.After(now) {
		return HWIDObservation0299{}, ErrNotFound
	}
	return v, nil
}
func (r *MemoryRepository) ConfirmHWID0299(_ context.Context, userID, deviceID string, now time.Time) (HWIDObservation0299, error) {
	d, err := r.GetTrustedDevice(userID, deviceID)
	if err != nil {
		return HWIDObservation0299{}, err
	}
	if d.Status != "active" {
		return HWIDObservation0299{}, ErrConflict
	}
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	k := userID + "\x00" + deviceID
	v, ok := r.hwidObservations[k]
	if !ok || !v.ExpiresAt.After(now) || v.State != "changed" || v.Pending == "" {
		return HWIDObservation0299{}, ErrNotFound
	}
	v.Baseline = v.Pending
	v.Pending = ""
	v.State = "recognized"
	v.UpdatedAt = now
	v.ExpiresAt = now.Add(hwidRetention0299)
	r.hwidObservations[k] = v
	return v, nil
}
func (r *MemoryRepository) ForgetHWID0299(_ context.Context, userID, deviceID string) error {
	d, err := r.GetTrustedDevice(userID, deviceID)
	if err != nil {
		return err
	}
	_ = d
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	delete(r.hwidObservations, userID+"\x00"+deviceID)
	for id, a := range r.hwidAppeals {
		if a.UserID == userID && a.DeviceID == deviceID {
			delete(r.hwidAppeals, id)
		}
	}
	return nil
}
func (r *MemoryRepository) SubmitHWIDAppeal0299(_ context.Context, a HWIDAppeal0299) error {
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	v, ok := r.hwidObservations[a.UserID+"\x00"+a.DeviceID]
	if !ok || v.State != "changed" || !v.ExpiresAt.After(a.CreatedAt) {
		return ErrConflict
	}
	if r.hwidAppeals == nil {
		r.hwidAppeals = map[string]HWIDAppeal0299{}
	}
	for _, prev := range r.hwidAppeals {
		if prev.UserID == a.UserID && prev.DeviceID == a.DeviceID && prev.Status == "pending" {
			return ErrConflict
		}
	}
	a.Pending = v.Pending
	a.Status = "pending"
	a.UpdatedAt = a.CreatedAt
	r.hwidAppeals[a.ID] = a
	return nil
}
func (r *MemoryRepository) ListHWIDAppeals0299(_ context.Context, userID string) ([]HWIDAppeal0299, error) {
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	out := []HWIDAppeal0299{}
	for _, a := range r.hwidAppeals {
		if userID == "" || a.UserID == userID {
			a.Pending = ""
			out = append(out, a)
		}
	}
	return out, nil
}
func (r *MemoryRepository) ResolveHWIDAppeal0299(_ context.Context, id, actor, decision string, now time.Time) (HWIDAppeal0299, error) {
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	a, ok := r.hwidAppeals[id]
	if !ok {
		return HWIDAppeal0299{}, ErrNotFound
	}
	if a.Status != "pending" {
		return HWIDAppeal0299{}, ErrConflict
	}
	if decision == "approved" {
		k := a.UserID + "\x00" + a.DeviceID
		v, ok := r.hwidObservations[k]
		if !ok || v.Pending != a.Pending || v.State != "changed" || !v.ExpiresAt.After(now) {
			return HWIDAppeal0299{}, ErrConflict
		}
		v.Baseline = v.Pending
		v.Pending = ""
		v.State = "recognized"
		v.UpdatedAt = now
		v.ExpiresAt = now.Add(hwidRetention0299)
		r.hwidObservations[k] = v
	}
	a.Status = decision
	a.Resolution = decision
	a.Actor = actor
	a.UpdatedAt = now
	r.hwidAppeals[id] = a
	a.Pending = ""
	return a, nil
}

// Utility intentionally excludes digests from all user-visible responses.
func PublicHWIDState0299(o HWIDObservation0299) map[string]any {
	return map[string]any{"deviceId": o.DeviceID, "state": strings.TrimSpace(o.State), "updatedAt": o.UpdatedAt, "expiresAt": o.ExpiresAt, "signalIsProofOfIdentity": false, "automaticBan": false}
}

// PruneHWID0299 physically removes expired observations and user appeals.
// Every API replica can run this; DELETE operations are idempotent. Expired
// observations are no longer consulted even if cleanup temporarily fails.
func (r *SQLRepository) PruneHWID0299(ctx context.Context, now time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM hwid_risk_appeals WHERE created_at<=$1`, now.Add(-hwidRetention0299)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM hwid_risk_observations WHERE expires_at<=$1`, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *MemoryRepository) PruneHWID0299(_ context.Context, now time.Time) error {
	r.hwidMu.Lock()
	defer r.hwidMu.Unlock()
	for key, o := range r.hwidObservations {
		if !o.ExpiresAt.After(now) {
			delete(r.hwidObservations, key)
		}
	}
	for key, a := range r.hwidAppeals {
		if !a.CreatedAt.Add(hwidRetention0299).After(now) {
			delete(r.hwidAppeals, key)
		}
	}
	return nil
}

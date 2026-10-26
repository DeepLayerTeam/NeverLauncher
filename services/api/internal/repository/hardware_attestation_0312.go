package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func validHardwareEvidence0312(v model.DeviceHardwareEvidence) bool {
	return v.UserID != "" && v.DeviceID != "" && v.SessionID != "" && v.BindingEpoch >= 1 && v.ChallengeID != "" && v.RootID != "" && len(v.RootFingerprint) == 64 && len(v.KeyFingerprint) == 64 && len(v.AKFingerprint) == 64 && !v.VerifiedAt.IsZero() && v.ExpiresAt.After(v.VerifiedAt) && v.ExpiresAt.Sub(v.VerifiedAt) <= time.Hour+time.Second
}

func (r *MemoryRepository) SaveHardwareEvidence(_ context.Context, e model.DeviceHardwareEvidence) error {
	if !validHardwareEvidence0312(e) {
		return errors.New("invalid hardware evidence")
	}
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	active := false
	for _, d := range r.trustedDevices {
		if d.ID == e.DeviceID && d.UserID == e.UserID && d.Status == "active" && d.TrustState == "verified" && d.KeyFingerprint == e.KeyFingerprint && d.KeyBinding == "hardware" && d.KeyAlgorithm == "p256" {
			active = true
			break
		}
	}
	if !active {
		return ErrNotFound
	}
	for _, item := range r.hardwareEvidence {
		if item.ChallengeID == e.ChallengeID {
			return ErrConflict
		}
	}
	r.hardwareEvidence = append(r.hardwareEvidence, e)
	return nil
}
func (r *MemoryRepository) LatestHardwareEvidence(_ context.Context, userID, deviceID string) (model.DeviceHardwareEvidence, error) {
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for i := len(r.hardwareEvidence) - 1; i >= 0; i-- {
		v := r.hardwareEvidence[i]
		if v.UserID == userID && v.DeviceID == deviceID {
			return v, nil
		}
	}
	return model.DeviceHardwareEvidence{}, ErrNotFound
}

func (r *SQLRepository) SaveHardwareEvidence(ctx context.Context, e model.DeviceHardwareEvidence) error {
	if err := r.check(); err != nil {
		return err
	}
	if !validHardwareEvidence0312(e) {
		return errors.New("invalid hardware evidence")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO device_hardware_evidence_0312(user_id,device_id,session_id,binding_epoch,key_fingerprint,root_id,root_fingerprint,ak_fingerprint,challenge_id,verified_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 FROM trusted_devices WHERE id=$2 AND user_id=$1 AND status='active' AND trust_state='verified' AND key_fingerprint=$5 AND key_binding='hardware' AND key_algorithm='p256'`, e.UserID, e.DeviceID, e.SessionID, e.BindingEpoch, strings.ToLower(e.KeyFingerprint), e.RootID, strings.ToLower(e.RootFingerprint), strings.ToLower(e.AKFingerprint), e.ChallengeID, e.VerifiedAt, e.ExpiresAt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
func (r *SQLRepository) LatestHardwareEvidence(ctx context.Context, userID, deviceID string) (model.DeviceHardwareEvidence, error) {
	if err := r.check(); err != nil {
		return model.DeviceHardwareEvidence{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var e model.DeviceHardwareEvidence
	err := r.db.QueryRowContext(ctx, `SELECT user_id,device_id,session_id,binding_epoch,key_fingerprint,root_id,root_fingerprint,ak_fingerprint,challenge_id,verified_at,expires_at FROM device_hardware_evidence_0312 WHERE user_id=$1 AND device_id=$2 ORDER BY verified_at DESC,id DESC LIMIT 1`, userID, deviceID).Scan(&e.UserID, &e.DeviceID, &e.SessionID, &e.BindingEpoch, &e.KeyFingerprint, &e.RootID, &e.RootFingerprint, &e.AKFingerprint, &e.ChallengeID, &e.VerifiedAt, &e.ExpiresAt)
	if err != nil {
		return model.DeviceHardwareEvidence{}, err
	}
	return e, nil
}

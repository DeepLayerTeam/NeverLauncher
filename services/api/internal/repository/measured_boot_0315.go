package repository

import (
	"context"
	"errors"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"strings"
	"time"
)

func validMeasuredBoot0315(e model.MeasuredBootEvidence0315) bool {
	return e.UserID != "" && e.DeviceID != "" && e.SessionID != "" && e.BindingEpoch > 0 && len(e.KeyFingerprint) == 64 && len(e.RootFingerprint) == 64 && len(e.AKFingerprint) == 64 && len(e.PolicyHash) == 64 && len(e.PCRDigest) == 64 && e.PolicyID != "" && e.ChallengeID != "" && !e.VerifiedAt.IsZero() && e.ExpiresAt.After(e.VerifiedAt) && e.ExpiresAt.Sub(e.VerifiedAt) <= 6*time.Minute
}
func (r *MemoryRepository) SaveMeasuredBoot0315(_ context.Context, e model.MeasuredBootEvidence0315) error {
	if !validMeasuredBoot0315(e) {
		return errors.New("invalid measured-boot evidence")
	}
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	found := false
	for _, d := range r.trustedDevices {
		if d.UserID == e.UserID && d.ID == e.DeviceID && d.Status == "active" && d.TrustState == "verified" && d.KeyFingerprint == e.KeyFingerprint && d.KeyBinding == "hardware" && d.KeyAlgorithm == "p256" {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	for _, item := range r.measuredBoot0315 {
		if item.ChallengeID == e.ChallengeID {
			return ErrConflict
		}
	}
	r.measuredBoot0315 = append(r.measuredBoot0315, e)
	return nil
}
func (r *MemoryRepository) LatestMeasuredBoot0315(_ context.Context, userID, deviceID string) (model.MeasuredBootEvidence0315, error) {
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	for i := len(r.measuredBoot0315) - 1; i >= 0; i-- {
		v := r.measuredBoot0315[i]
		if v.UserID == userID && v.DeviceID == deviceID {
			return v, nil
		}
	}
	return model.MeasuredBootEvidence0315{}, ErrNotFound
}
func (r *SQLRepository) SaveMeasuredBoot0315(ctx context.Context, e model.MeasuredBootEvidence0315) error {
	if err := r.check(); err != nil {
		return err
	}
	if !validMeasuredBoot0315(e) {
		return errors.New("invalid measured-boot evidence")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO device_measured_boot_0315 (user_id,device_id,session_id,binding_epoch,key_fingerprint,root_id,root_fingerprint,ak_fingerprint,policy_id,policy_hash,pcr_digest,challenge_id,verified_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14 FROM trusted_devices WHERE id=$2 AND user_id=$1 AND status='active' AND trust_state='verified' AND key_fingerprint=$5 AND key_binding='hardware' AND key_algorithm='p256'`, e.UserID, e.DeviceID, e.SessionID, e.BindingEpoch, strings.ToLower(e.KeyFingerprint), e.RootID, e.RootFingerprint, e.AKFingerprint, e.PolicyID, e.PolicyHash, e.PCRDigest, e.ChallengeID, e.VerifiedAt, e.ExpiresAt)
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
func (r *SQLRepository) LatestMeasuredBoot0315(ctx context.Context, userID, deviceID string) (model.MeasuredBootEvidence0315, error) {
	if err := r.check(); err != nil {
		return model.MeasuredBootEvidence0315{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var e model.MeasuredBootEvidence0315
	err := r.db.QueryRowContext(ctx, `SELECT user_id,device_id,session_id,binding_epoch,key_fingerprint,root_id,root_fingerprint,ak_fingerprint,policy_id,policy_hash,pcr_digest,challenge_id,verified_at,expires_at FROM device_measured_boot_0315 WHERE user_id=$1 AND device_id=$2 ORDER BY verified_at DESC,id DESC LIMIT 1`, userID, deviceID).Scan(&e.UserID, &e.DeviceID, &e.SessionID, &e.BindingEpoch, &e.KeyFingerprint, &e.RootID, &e.RootFingerprint, &e.AKFingerprint, &e.PolicyID, &e.PolicyHash, &e.PCRDigest, &e.ChallengeID, &e.VerifiedAt, &e.ExpiresAt)
	if err != nil {
		return model.MeasuredBootEvidence0315{}, err
	}
	return e, nil
}

package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Staged challenges are authoritative: a fabricated or replayed grant cannot
// create a matching persisted run challenge. Keys are revoked monotonically.
func (r *MemoryRepository) SaveValidationChallenge0346(_ context.Context, c model.ValidationChallenge0346) error {
	if c.RunID == "" || c.Nonce == "" || c.PackageID == "" || c.ExpiresAt.Before(c.IssuedAt) || len(c.TargetMatrixSHA256) != 64 {
		return errors.New("invalid validation challenge")
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	if r.validationChallenges0346 == nil {
		r.validationChallenges0346 = make(map[string]model.ValidationChallenge0346)
	}
	for _, old := range r.validationChallenges0346 {
		if old.Nonce == c.Nonce {
			return ErrConflict
		}
	}
	if _, ok := r.validationChallenges0346[c.RunID]; ok {
		return ErrConflict
	}
	r.validationChallenges0346[c.RunID] = c
	return nil
}
func (r *MemoryRepository) GetValidationChallenge0346(_ context.Context, runID string) (model.ValidationChallenge0346, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	v, ok := r.validationChallenges0346[runID]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r *MemoryRepository) IsValidationKeyRevoked0346(_ context.Context, fingerprint string) (bool, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	return r.validationRevocations0346[fingerprint], nil
}
func (r *MemoryRepository) RevokeValidationKey0346(_ context.Context, fingerprint, actor, reason string) error {
	if len(fingerprint) != 64 || strings.TrimSpace(reason) == "" || strings.TrimSpace(actor) == "" {
		return errors.New("invalid validation key revocation")
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	if r.validationRevocations0346 == nil {
		r.validationRevocations0346 = map[string]bool{}
	}
	r.validationRevocations0346[fingerprint] = true
	return nil
}
func (r *SQLRepository) SaveValidationChallenge0346(ctx context.Context, c model.ValidationChallenge0346) error {
	if err := r.check(); err != nil {
		return err
	}
	if c.RunID == "" || c.Nonce == "" || c.PackageID == "" || !c.ExpiresAt.After(c.IssuedAt) || len(c.TargetMatrixSHA256) != 64 {
		return errors.New("invalid validation challenge")
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO package_validation_challenges_0346(run_id,nonce,package_id,project_id,manifest_sha256,artifact_sha256,target_matrix_sha256,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, c.RunID, c.Nonce, c.PackageID, c.ProjectID, c.ManifestSHA256, c.ArtifactSHA256, c.TargetMatrixSHA256, c.IssuedAt, c.ExpiresAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return nil
}
func (r *SQLRepository) GetValidationChallenge0346(ctx context.Context, id string) (model.ValidationChallenge0346, error) {
	var c model.ValidationChallenge0346
	if err := r.check(); err != nil {
		return c, err
	}
	err := r.db.QueryRowContext(ctx, `SELECT run_id,nonce,package_id,project_id,manifest_sha256,artifact_sha256,target_matrix_sha256,issued_at,expires_at FROM package_validation_challenges_0346 WHERE run_id=$1`, id).Scan(&c.RunID, &c.Nonce, &c.PackageID, &c.ProjectID, &c.ManifestSHA256, &c.ArtifactSHA256, &c.TargetMatrixSHA256, &c.IssuedAt, &c.ExpiresAt)
	return c, err
}
func (r *SQLRepository) IsValidationKeyRevoked0346(ctx context.Context, id string) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	var revoked bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM package_validation_revoked_keys_0346 WHERE fingerprint=$1)`, id).Scan(&revoked)
	return revoked, err
}
func (r *SQLRepository) RevokeValidationKey0346(ctx context.Context, id, actor, reason string) error {
	if err := r.check(); err != nil {
		return err
	}
	if len(id) != 64 || strings.TrimSpace(actor) == "" || strings.TrimSpace(reason) == "" {
		return errors.New("invalid validation key revocation")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('validation-signer:'||$1,0))`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO package_validation_revoked_keys_0346(fingerprint,actor,reason,revoked_at) VALUES($1,$2,$3,$4) ON CONFLICT(fingerprint) DO NOTHING`, id, actor, reason, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

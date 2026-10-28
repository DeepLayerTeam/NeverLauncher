package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Exact run retrieval makes older attempts reproducible despite bounded
// list endpoints and protects access by the enclosing package identity.
func (r *MemoryRepository) GetValidationRun03412(_ context.Context, pkg, run string) (model.StagedRuntimeRun0342, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for _, value := range r.stagedRuntimeRuns0342 {
		if value.PackageID == pkg && value.RunID == run {
			value.Stages = append([]byte(nil), value.Stages...)
			return value, nil
		}
	}
	return model.StagedRuntimeRun0342{}, ErrNotFound
}
func (r *SQLRepository) GetValidationRun03412(ctx context.Context, pkg, run string) (model.StagedRuntimeRun0342, error) {
	var v model.StagedRuntimeRun0342
	if err := r.check(); err != nil {
		return v, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := r.db.QueryRowContext(ctx, `SELECT run_id,package_id,project_id,manifest_sha256,artifact_sha256,stages,started_at,finished_at,received_at FROM package_staged_runtime_runs_0342 WHERE package_id=$1 AND run_id=$2`, pkg, run).Scan(
		&v.RunID, &v.PackageID, &v.ProjectID, &v.ManifestSHA256, &v.ArtifactSHA256, &v.Stages, &v.StartedAt, &v.FinishedAt, &v.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}
func (r *MemoryRepository) GetValidationEvidence03412(_ context.Context, pkg, run string) (model.ValidationAttestation0345, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for _, value := range r.validationAttestations0345 {
		if value.PackageID == pkg && value.RunID == run {
			value.Evidence = append([]byte(nil), value.Evidence...)
			return value, nil
		}
	}
	return model.ValidationAttestation0345{}, ErrNotFound
}
func (r *SQLRepository) GetValidationEvidence03412(ctx context.Context, pkg, run string) (model.ValidationAttestation0345, error) {
	var v model.ValidationAttestation0345
	if err := r.check(); err != nil {
		return v, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := r.db.QueryRowContext(ctx, `SELECT run_id,package_id,project_id,manifest_sha256,artifact_sha256,evidence,signature,received_at FROM package_validation_attestations_0345 WHERE package_id=$1 AND run_id=$2`, pkg, run).Scan(
		&v.RunID, &v.PackageID, &v.ProjectID, &v.ManifestSHA256, &v.ArtifactSHA256, &v.Evidence, &v.Signature, &v.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}
func validRunID03412(run string) bool {
	if len(run) < 1 || len(run) > 160 {
		return false
	}
	for _, b := range []byte(strings.ToLower(run)) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

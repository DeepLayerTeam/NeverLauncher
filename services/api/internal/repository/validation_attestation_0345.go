package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func validAttestation0345(v model.ValidationAttestation0345) error {
	if v.RunID == "" || v.PackageID == "" || v.ProjectID == "" || len(v.ManifestSHA256) != 64 || len(v.ArtifactSHA256) != 64 || len(v.Signature) < 80 || !json.Valid(v.Evidence) {
		return errors.New("invalid attestation")
	}
	return nil
}
func (r *MemoryRepository) SaveValidationAttestation0345(_ context.Context, v model.ValidationAttestation0345) error {
	if e := validAttestation0345(v); e != nil {
		return e
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for _, old := range r.validationAttestations0345 {
		if old.RunID == v.RunID {
			return ErrConflict
		}
	}
	r.validationAttestations0345 = append(r.validationAttestations0345, v)
	return nil
}
func (r *MemoryRepository) ListValidationAttestations0345(_ context.Context, packageID string) ([]model.ValidationAttestation0345, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	out := []model.ValidationAttestation0345{}
	for i := len(r.validationAttestations0345) - 1; i >= 0; i-- {
		v := r.validationAttestations0345[i]
		if v.PackageID == strings.TrimSpace(packageID) {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *SQLRepository) SaveValidationAttestation0345(ctx context.Context, v model.ValidationAttestation0345) error {
	if e := r.check(); e != nil {
		return e
	}
	if e := validAttestation0345(v); e != nil {
		return e
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result, e := r.db.ExecContext(ctx, `INSERT INTO package_validation_attestations_0345(run_id,package_id,project_id,manifest_sha256,artifact_sha256,evidence,signature,received_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8) ON CONFLICT DO NOTHING`, v.RunID, v.PackageID, v.ProjectID, v.ManifestSHA256, v.ArtifactSHA256, string(v.Evidence), v.Signature, v.ReceivedAt)
	if e != nil {
		return e
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return nil
}
func (r *SQLRepository) ListValidationAttestations0345(ctx context.Context, packageID string) ([]model.ValidationAttestation0345, error) {
	if e := r.check(); e != nil {
		return nil, e
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, e := r.db.QueryContext(ctx, `SELECT run_id,package_id,project_id,manifest_sha256,artifact_sha256,evidence,signature,received_at FROM package_validation_attestations_0345 WHERE package_id=$1 ORDER BY received_at DESC LIMIT 100`, strings.TrimSpace(packageID))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.ValidationAttestation0345{}
	for rows.Next() {
		var v model.ValidationAttestation0345
		if e := rows.Scan(&v.RunID, &v.PackageID, &v.ProjectID, &v.ManifestSHA256, &v.ArtifactSHA256, &v.Evidence, &v.Signature, &v.ReceivedAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

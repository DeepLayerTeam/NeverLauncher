package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func normalizeIntegrityResult0212(in model.IntegrityCheckResult) (model.IntegrityCheckResult, error) {
	in.ID = strings.TrimSpace(in.ID)
	in.PackageID = strings.TrimSpace(in.PackageID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.ManifestDigest = strings.ToLower(strings.TrimSpace(in.ManifestDigest))
	in.ArtifactDigest = strings.ToLower(strings.TrimSpace(in.ArtifactDigest))
	in.Result = strings.ToLower(strings.TrimSpace(in.Result))
	if in.ID == "" || in.PackageID == "" || in.ProjectID == "" || len(in.ManifestDigest) != 64 || len(in.ArtifactDigest) != 64 {
		return model.IntegrityCheckResult{}, errors.New("integrity result identity/digests are incomplete")
	}
	if in.Result != "passed" && in.Result != "failed" {
		return model.IntegrityCheckResult{}, errors.New("integrity result must be passed or failed")
	}
	if in.CheckedAt.IsZero() {
		in.CheckedAt = time.Now().UTC()
	}
	return in, nil
}

func normalizeRuntimeValidation0212(in model.RuntimeValidationResult) (model.RuntimeValidationResult, error) {
	in.ID = strings.TrimSpace(in.ID)
	in.PackageID = strings.TrimSpace(in.PackageID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.ManifestDigest = strings.ToLower(strings.TrimSpace(in.ManifestDigest))
	in.TargetID = strings.TrimSpace(in.TargetID)
	in.RunID = strings.TrimSpace(in.RunID)
	in.SignerKeyID = strings.TrimSpace(in.SignerKeyID)
	in.SignerKeyFingerprint = strings.ToLower(strings.TrimSpace(in.SignerKeyFingerprint))
	in.EvidenceDigest = strings.ToLower(strings.TrimSpace(in.EvidenceDigest))
	in.Result = strings.ToLower(strings.TrimSpace(in.Result))
	if in.ID == "" || in.PackageID == "" || in.ProjectID == "" || len(in.ManifestDigest) != 64 || len(in.EvidenceDigest) != 64 || in.TargetID == "" || in.RunID == "" || in.SignerKeyID == "" || len(in.SignerKeyFingerprint) != 64 {
		return model.RuntimeValidationResult{}, errors.New("runtime validation identity/digests are incomplete")
	}
	if in.Result != "passed" && in.Result != "failed" {
		return model.RuntimeValidationResult{}, errors.New("runtime validation result must be passed or failed")
	}
	if in.Result == "passed" && (!in.ActualClient || in.ExitCode != 0) {
		return model.RuntimeValidationResult{}, errors.New("runtime validation pass requires actual client evidence with exit code 0")
	}
	if in.FinishedAt.IsZero() || in.StartedAt.IsZero() || in.FinishedAt.Before(in.StartedAt) {
		return model.RuntimeValidationResult{}, errors.New("runtime validation timestamps are invalid")
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	return in, nil
}

func (r *MemoryRepository) SaveIntegrityCheck(ctx context.Context, result model.IntegrityCheckResult) (model.IntegrityCheckResult, error) {
	_ = ctx
	result, err := normalizeIntegrityResult0212(result)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	r.integrityChecks = append(r.integrityChecks, result)
	return result, nil
}

func (r *MemoryRepository) LatestIntegrityCheck(ctx context.Context, packageID string) (model.IntegrityCheckResult, error) {
	_ = ctx
	packageID = strings.TrimSpace(packageID)
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for i := len(r.integrityChecks) - 1; i >= 0; i-- {
		if r.integrityChecks[i].PackageID == packageID {
			return r.integrityChecks[i], nil
		}
	}
	return model.IntegrityCheckResult{}, ErrNotFound
}

func (r *MemoryRepository) SaveRuntimeValidation(ctx context.Context, result model.RuntimeValidationResult) (model.RuntimeValidationResult, error) {
	_ = ctx
	result, err := normalizeRuntimeValidation0212(result)
	if err != nil {
		return model.RuntimeValidationResult{}, err
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for _, existing := range r.runtimeValidations {
		if existing.ID == result.ID || (existing.RunID != "" && existing.RunID == result.RunID && existing.TargetID == result.TargetID && existing.PackageID == result.PackageID) {
			return model.RuntimeValidationResult{}, ErrConflict
		}
	}
	r.runtimeValidations = append(r.runtimeValidations, result)
	return result, nil
}

func (r *MemoryRepository) ListRuntimeValidations(ctx context.Context, packageID string) ([]model.RuntimeValidationResult, error) {
	_ = ctx
	packageID = strings.TrimSpace(packageID)
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	out := make([]model.RuntimeValidationResult, 0)
	for _, v := range r.runtimeValidations {
		if v.PackageID == packageID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FinishedAt.After(out[j].FinishedAt) })
	return out, nil
}

func (r *SQLRepository) SaveIntegrityCheck(ctx context.Context, result model.IntegrityCheckResult) (model.IntegrityCheckResult, error) {
	if err := r.check(); err != nil {
		return model.IntegrityCheckResult{}, err
	}
	result, err := normalizeIntegrityResult0212(result)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	checks, err := json.Marshal(result.Checks)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO package_integrity_checks(id,package_id,project_id,manifest_digest,artifact_digest,signature_verified,storage_verified,files_verified,compatibility_verified,result,checks,checked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`, result.ID, result.PackageID, result.ProjectID, result.ManifestDigest, result.ArtifactDigest, result.SignatureVerified, result.StorageVerified, result.FilesVerified, result.CompatibilityVerified, result.Result, string(checks), result.CheckedAt)
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	return result, nil
}

func (r *SQLRepository) LatestIntegrityCheck(ctx context.Context, packageID string) (model.IntegrityCheckResult, error) {
	if err := r.check(); err != nil {
		return model.IntegrityCheckResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var out model.IntegrityCheckResult
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT id,package_id,project_id,manifest_digest,artifact_digest,signature_verified,storage_verified,files_verified,compatibility_verified,result,checks,checked_at FROM package_integrity_checks WHERE package_id=$1 ORDER BY checked_at DESC,id DESC LIMIT 1`, strings.TrimSpace(packageID)).Scan(&out.ID, &out.PackageID, &out.ProjectID, &out.ManifestDigest, &out.ArtifactDigest, &out.SignatureVerified, &out.StorageVerified, &out.FilesVerified, &out.CompatibilityVerified, &out.Result, &raw, &out.CheckedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.IntegrityCheckResult{}, ErrNotFound
	}
	if err != nil {
		return model.IntegrityCheckResult{}, err
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out.Checks)
	}
	return out, nil
}

func (r *SQLRepository) SaveRuntimeValidation(ctx context.Context, result model.RuntimeValidationResult) (model.RuntimeValidationResult, error) {
	if err := r.check(); err != nil {
		return model.RuntimeValidationResult{}, err
	}
	result, err := normalizeRuntimeValidation0212(result)
	if err != nil {
		return model.RuntimeValidationResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	hashes, err := json.Marshal(result.EvidenceHashes)
	if err != nil {
		return model.RuntimeValidationResult{}, err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO package_runtime_validations(id,package_id,project_id,manifest_digest,target_id,minecraft_version,loader,os,arch,java_runtime,actual_client,exit_code,server_join,run_id,commit_sha,evidence_hashes,signer_key_id,signer_key_fingerprint,evidence_digest,started_at,finished_at,result,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18,$19,$20,$21,$22,$23)`, result.ID, result.PackageID, result.ProjectID, result.ManifestDigest, result.TargetID, result.MinecraftVersion, result.Loader, result.OS, result.Arch, result.Java, result.ActualClient, result.ExitCode, result.ServerJoin, result.RunID, result.Commit, string(hashes), result.SignerKeyID, result.SignerKeyFingerprint, result.EvidenceDigest, result.StartedAt, result.FinishedAt, result.Result, result.CreatedAt)
	if err != nil {
		return model.RuntimeValidationResult{}, err
	}
	return result, nil
}

func (r *SQLRepository) ListRuntimeValidations(ctx context.Context, packageID string) ([]model.RuntimeValidationResult, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,package_id,project_id,manifest_digest,target_id,minecraft_version,loader,os,arch,java_runtime,actual_client,exit_code,server_join,run_id,commit_sha,evidence_hashes,signer_key_id,signer_key_fingerprint,evidence_digest,started_at,finished_at,result,created_at FROM package_runtime_validations WHERE package_id=$1 ORDER BY finished_at DESC,id DESC`, strings.TrimSpace(packageID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RuntimeValidationResult{}
	for rows.Next() {
		var v model.RuntimeValidationResult
		var raw []byte
		if err := rows.Scan(&v.ID, &v.PackageID, &v.ProjectID, &v.ManifestDigest, &v.TargetID, &v.MinecraftVersion, &v.Loader, &v.OS, &v.Arch, &v.Java, &v.ActualClient, &v.ExitCode, &v.ServerJoin, &v.RunID, &v.Commit, &raw, &v.SignerKeyID, &v.SignerKeyFingerprint, &v.EvidenceDigest, &v.StartedAt, &v.FinishedAt, &v.Result, &v.CreatedAt); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &v.EvidenceHashes)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func normalizeProjectValidationPolicy0212(in model.ProjectValidationPolicy) (model.ProjectValidationPolicy, error) {
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.RequiredLevel = strings.ToLower(strings.TrimSpace(in.RequiredLevel))
	if in.ProjectID == "" {
		return model.ProjectValidationPolicy{}, errors.New("project validation policy requires projectId")
	}
	if in.RequiredLevel == "" {
		in.RequiredLevel = "integrity"
	}
	if in.RequiredLevel != "integrity" && in.RequiredLevel != "runtime" {
		return model.ProjectValidationPolicy{}, errors.New("required validation level must be integrity or runtime")
	}
	if in.UpdatedAt.IsZero() {
		in.UpdatedAt = time.Now().UTC()
	}
	return in, nil
}

func (r *MemoryRepository) GetProjectValidationPolicy(ctx context.Context, projectID string) (model.ProjectValidationPolicy, error) {
	_ = ctx
	projectID = strings.TrimSpace(projectID)
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	if p, ok := r.validationPolicies[projectID]; ok {
		return p, nil
	}
	for _, p := range r.projects {
		if p.ID == projectID {
			out := model.ProjectValidationPolicy{ProjectID: projectID, RequiredLevel: "integrity", UpdatedAt: time.Now().UTC()}
			r.validationPolicies[projectID] = out
			return out, nil
		}
	}
	return model.ProjectValidationPolicy{}, ErrNotFound
}

func (r *MemoryRepository) SaveProjectValidationPolicy(ctx context.Context, policy model.ProjectValidationPolicy) (model.ProjectValidationPolicy, error) {
	_ = ctx
	policy, err := normalizeProjectValidationPolicy0212(policy)
	if err != nil {
		return model.ProjectValidationPolicy{}, err
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	found := false
	for _, p := range r.projects {
		if p.ID == policy.ProjectID {
			found = true
			break
		}
	}
	if !found {
		return model.ProjectValidationPolicy{}, ErrNotFound
	}
	r.validationPolicies[policy.ProjectID] = policy
	return policy, nil
}

func (r *SQLRepository) GetProjectValidationPolicy(ctx context.Context, projectID string) (model.ProjectValidationPolicy, error) {
	if err := r.check(); err != nil {
		return model.ProjectValidationPolicy{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	projectID = strings.TrimSpace(projectID)
	_, _ = r.db.ExecContext(ctx, `INSERT INTO project_validation_policies(project_id,required_level,require_server_join) SELECT id,'integrity',false FROM projects WHERE id=$1 ON CONFLICT(project_id) DO NOTHING`, projectID)
	var p model.ProjectValidationPolicy
	err := r.db.QueryRowContext(ctx, `SELECT project_id,required_level,require_server_join,updated_at FROM project_validation_policies WHERE project_id=$1`, projectID).Scan(&p.ProjectID, &p.RequiredLevel, &p.RequireServerJoin, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ProjectValidationPolicy{}, ErrNotFound
	}
	if err != nil {
		return model.ProjectValidationPolicy{}, err
	}
	return p, nil
}

func (r *SQLRepository) SaveProjectValidationPolicy(ctx context.Context, policy model.ProjectValidationPolicy) (model.ProjectValidationPolicy, error) {
	if err := r.check(); err != nil {
		return model.ProjectValidationPolicy{}, err
	}
	policy, err := normalizeProjectValidationPolicy0212(policy)
	if err != nil {
		return model.ProjectValidationPolicy{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	row := r.db.QueryRowContext(ctx, `INSERT INTO project_validation_policies(project_id,required_level,require_server_join,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(project_id) DO UPDATE SET required_level=EXCLUDED.required_level,require_server_join=EXCLUDED.require_server_join,updated_at=EXCLUDED.updated_at RETURNING project_id,required_level,require_server_join,updated_at`, policy.ProjectID, policy.RequiredLevel, policy.RequireServerJoin, policy.UpdatedAt)
	var out model.ProjectValidationPolicy
	if err := row.Scan(&out.ProjectID, &out.RequiredLevel, &out.RequireServerJoin, &out.UpdatedAt); err != nil {
		return model.ProjectValidationPolicy{}, err
	}
	return out, nil
}

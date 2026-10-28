package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func validStagedRun0342(v model.StagedRuntimeRun0342) error {
	if v.RunID == "" || v.PackageID == "" || v.ProjectID == "" || len(v.ManifestSHA256) != 64 || len(v.ArtifactSHA256) != 64 || len(v.Stages) == 0 || !json.Valid(v.Stages) || v.StartedAt.IsZero() || v.FinishedAt.Before(v.StartedAt) {
		return errors.New("invalid staged runtime report")
	}
	return nil
}
func (r *MemoryRepository) SaveStagedRun0342(_ context.Context, v model.StagedRuntimeRun0342) error {
	if err := validStagedRun0342(v); err != nil {
		return err
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for _, old := range r.stagedRuntimeRuns0342 {
		if old.RunID == v.RunID {
			return ErrConflict
		}
	}
	r.stagedRuntimeRuns0342 = append(r.stagedRuntimeRuns0342, v)
	return nil
}
func (r *MemoryRepository) ListStagedRuns0342(_ context.Context, packageID string) ([]model.StagedRuntimeRun0342, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	out := []model.StagedRuntimeRun0342{}
	for i := len(r.stagedRuntimeRuns0342) - 1; i >= 0; i-- {
		v := r.stagedRuntimeRuns0342[i]
		if v.PackageID == strings.TrimSpace(packageID) {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *SQLRepository) SaveStagedRun0342(ctx context.Context, v model.StagedRuntimeRun0342) error {
	if err := r.check(); err != nil {
		return err
	}
	if err := validStagedRun0342(v); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO package_staged_runtime_runs_0342(run_id,package_id,project_id,manifest_sha256,artifact_sha256,stages,started_at,finished_at,received_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9) ON CONFLICT DO NOTHING`, v.RunID, v.PackageID, v.ProjectID, v.ManifestSHA256, v.ArtifactSHA256, string(v.Stages), v.StartedAt, v.FinishedAt, v.ReceivedAt)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	return nil
}
func (r *SQLRepository) ListStagedRuns0342(ctx context.Context, packageID string) ([]model.StagedRuntimeRun0342, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := r.db.QueryContext(ctx, `SELECT run_id,package_id,project_id,manifest_sha256,artifact_sha256,stages,started_at,finished_at,received_at FROM package_staged_runtime_runs_0342 WHERE package_id=$1 ORDER BY received_at DESC LIMIT 100`, strings.TrimSpace(packageID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.StagedRuntimeRun0342{}
	for rows.Next() {
		var v model.StagedRuntimeRun0342
		if err := rows.Scan(&v.RunID, &v.PackageID, &v.ProjectID, &v.ManifestSHA256, &v.ArtifactSHA256, &v.Stages, &v.StartedAt, &v.FinishedAt, &v.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

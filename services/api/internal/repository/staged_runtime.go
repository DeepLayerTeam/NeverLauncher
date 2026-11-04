package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func sanitizePersistedStages03412(raw json.RawMessage) json.RawMessage {
	var stages map[string]struct {
		Status         string `json:"status"`
		Detail         string `json:"detail,omitempty"`
		EvidenceSHA256 string `json:"evidenceSha256,omitempty"`
	}
	if json.Unmarshal(raw, &stages) != nil {
		return raw
	}
	for name, item := range stages {
		item.Detail = model.RedactValidationDetail03412(item.Detail)
		stages[name] = item
	}
	safe, err := json.Marshal(stages)
	if err != nil {
		return raw
	}
	return safe
}
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
	v.Stages = sanitizePersistedStages03412(v.Stages)
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	for _, old := range r.stagedRuntimeRuns0342 {
		if old.RunID == v.RunID {
			return ErrConflict
		}
	}
	v.Stages = append(json.RawMessage(nil), v.Stages...)
	r.stagedRuntimeRuns0342 = append(r.stagedRuntimeRuns0342, v)
	// In-memory repository mirrors the PostgreSQL AFTER INSERT audit trigger.
	digest := sha256.Sum256(v.Stages)
	r.validationAttempts03412 = append(r.validationAttempts03412, model.ValidationAttempt03412{
		ID: int64(len(r.validationAttempts03412) + 1), PackageID: v.PackageID, RunID: v.RunID,
		Kind: "staged-report", Outcome: "recorded", ReasonCode: "untrusted-observation", PayloadSHA256: hex.EncodeToString(digest[:]), CreatedAt: time.Now().UTC()})
	return nil
}
func (r *MemoryRepository) ListStagedRuns0342(_ context.Context, packageID string) ([]model.StagedRuntimeRun0342, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	out := []model.StagedRuntimeRun0342{}
	for i := len(r.stagedRuntimeRuns0342) - 1; i >= 0; i-- {
		v := r.stagedRuntimeRuns0342[i]
		if v.PackageID == strings.TrimSpace(packageID) {
			v.Stages = append(json.RawMessage(nil), v.Stages...)
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
	v.Stages = sanitizePersistedStages03412(v.Stages)
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
		v.Stages = append(json.RawMessage(nil), v.Stages...)
		out = append(out, v)
	}
	return out, rows.Err()
}

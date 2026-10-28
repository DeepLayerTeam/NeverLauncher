package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	co "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcutover"
	gr "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitrehearsal"
	rb "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitrollback"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func rollbackTx03312(ctx context.Context, r *SQLRepository, run string) (*sql.Tx, string, error) {
	if e := r.check(); e != nil {
		return nil, "", e
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return nil, "", e
	}
	var project string
	e = tx.QueryRowContext(ctx, `SELECT project_id FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, run).Scan(&project)
	if errors.Is(e, sql.ErrNoRows) {
		tx.Rollback()
		return nil, "", mw.ErrNotFound
	}
	if e != nil {
		tx.Rollback()
		return nil, "", e
	}
	// Shared lock order with MIG11 and ordinary publication.
	var locked string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM projects WHERE id=$1 FOR UPDATE`, project).Scan(&locked); e != nil {
		tx.Rollback()
		return nil, "", e
	}
	return tx, project, nil
}
func rollbackRoute03312(ctx context.Context, tx *sql.Tx, run, profile, channel string) (co.Route, error) {
	return cutoverScan03311(tx.QueryRowContext(ctx, `SELECT `+cutoverFields03311+` FROM migration_cutovers_03311 WHERE run_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, run, profile, channel))
}
func rollbackRehearsal03312(ctx context.Context, tx *sql.Tx, run string) (gr.Report, error) {
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT report FROM migration_rehearsals_03310 WHERE run_id=$1 ORDER BY recorded_at DESC,stage_id DESC LIMIT 1`, run).Scan(&raw); e != nil {
		return gr.Report{}, mw.ErrConflict
	}
	var rep gr.Report
	if json.Unmarshal(raw, &rep) != nil {
		return gr.Report{}, mw.ErrConflict
	}
	return rep, nil
}
func rollbackHead03312(ctx context.Context, tx *sql.Tx, v co.Route) error {
	var id, ver, digest string
	var revision int64
	e := tx.QueryRowContext(ctx, `SELECT release_id,version,manifest_digest,revision FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, v.ProjectID, v.ProfileID, v.Channel).Scan(&id, &ver, &digest, &revision)
	if e != nil || v.ActivatedRevision == nil || revision != *v.ActivatedRevision || id != v.ReleaseID || ver != v.ReleaseVersion || digest != v.TargetDigest {
		return mw.ErrConflict
	}
	return nil
}

// PlanMigrationRollback03312 evaluates ACTUAL structured world/player snapshots
// against the MIG10 baseline, not a user-supplied "ready" boolean. A nonempty
// diff blocks automatic rollback; no world or plugin DB is ever overwritten.
func (r *SQLRepository) PlanMigrationRollback03312(ctx context.Context, run string, input rb.PlanInput) (rb.Result, error) {
	if e := rb.ValidatePlan(input); e != nil {
		return rb.Result{}, e
	}
	tx, project, e := rollbackTx03312(ctx, r, run)
	if e != nil {
		return rb.Result{}, e
	}
	defer tx.Rollback()
	v, e := rollbackRoute03312(ctx, tx, run, input.ProfileID, input.Channel)
	if e != nil {
		return rb.Result{}, e
	}
	if v.ProjectID != project || v.State != "active" || v.Revision != input.ExpectedRevision {
		return rb.Result{}, mw.ErrConflict
	}
	if e = rollbackHead03312(ctx, tx, v); e != nil {
		return rb.Result{}, e
	}
	rep, e := rollbackRehearsal03312(ctx, tx, run)
	if e != nil || rep.StageID != v.StageID {
		return rb.Result{}, mw.ErrConflict
	}
	result, e := rb.Compare(input, rep, run)
	if e != nil {
		return rb.Result{}, e
	}
	// Record a blocked attempt in migration audit, without authorizing a route change.
	if !result.Ready {
		if e = eventRollback03312(ctx, tx, run, "gravit_rollback_blocked", result); e != nil {
			return rb.Result{}, e
		}
		if e = tx.Commit(); e != nil {
			return rb.Result{}, e
		}
		return result, nil
	}
	var stored rb.Result
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT result FROM migration_rollbacks_03312 WHERE run_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, run, input.ProfileID, input.Channel).Scan(&raw)
	if err == nil {
		if json.Unmarshal(raw, &stored) != nil || stored.PlanSHA256 != result.PlanSHA256 {
			return rb.Result{}, mw.ErrConflict
		}
		if e = tx.Commit(); e != nil {
			return rb.Result{}, e
		}
		return stored, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rb.Result{}, err
	}
	result.State = "planned"
	raw, _ = json.Marshal(result)
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_rollbacks_03312(run_id,project_id,profile_id,channel,plan_sha256,baseline_snapshot_sha256,current_snapshot_sha256,evidence_sha256,evidence_reference,route_revision,result)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, run, project, input.ProfileID, input.Channel, result.PlanSHA256, result.BaselineSnapshotSHA256, result.CurrentSnapshotSHA256, result.EvidenceSHA256, result.EvidenceReference, result.RouteRevision, string(raw))
	if e != nil {
		return rb.Result{}, e
	}
	if e = eventRollback03312(ctx, tx, run, "gravit_rollback_planned", result); e != nil {
		return rb.Result{}, e
	}
	if e = tx.Commit(); e != nil {
		return rb.Result{}, fmt.Errorf("rollback plan commit uncertain; GET before retry: %w", e)
	}
	return result, nil
}

// CommitMigrationRollback03312 modifies only the actual Never delivery pointer.
// The source system remains externally fenced and is never resumed by this call.
func (r *SQLRepository) CommitMigrationRollback03312(ctx context.Context, run string, input rb.CommitInput, trusted ed25519.PublicKey) (rb.Result, error) {
	if e := rb.ValidateCommit(input); e != nil {
		return rb.Result{}, e
	}
	tx, project, e := rollbackTx03312(ctx, r, run)
	if e != nil {
		return rb.Result{}, e
	}
	defer tx.Rollback()
	v, e := rollbackRoute03312(ctx, tx, run, input.ProfileID, input.Channel)
	if e != nil {
		return rb.Result{}, e
	}
	if v.ProjectID != project {
		return rb.Result{}, mw.ErrConflict
	}
	var raw []byte
	var planned time.Time
	var state string
	e = tx.QueryRowContext(ctx, `SELECT result,planned_at,state FROM migration_rollbacks_03312 WHERE run_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, run, input.ProfileID, input.Channel).Scan(&raw, &planned, &state)
	if e != nil {
		return rb.Result{}, mw.ErrConflict
	}
	var result rb.Result
	if json.Unmarshal(raw, &result) != nil || !result.Ready || result.PlanSHA256 != input.PlanSHA256 || result.RouteRevision != input.ExpectedRevision {
		return rb.Result{}, mw.ErrConflict
	}
	if state == "completed" {
		if v.State != "rolled_back" || v.Revision != input.ExpectedRevision+1 {
			return rb.Result{}, mw.ErrConflict
		}
		if e = tx.Commit(); e != nil {
			return rb.Result{}, e
		}
		return result, nil
	}
	freshDigest, e := gr.SnapshotDigest(input.Current)
	if e != nil || freshDigest != result.CurrentSnapshotSHA256 || !rb.ValidSHA256(input.CurrentEvidenceSHA256) {
		return rb.Result{}, mw.ErrConflict
	}
	// Reconciliation receipts are only usable while BOTH sides still match.
	if result.Mode == "reconciled" {
		if input.ReconciledSource == nil || input.ReconciliationEvidenceSHA256 != result.ReconciliationEvidenceSHA256 {
			return rb.Result{}, mw.ErrConflict
		}
		verifiedSource, e := gr.SnapshotDigest(*input.ReconciledSource)
		if e != nil || verifiedSource != result.ReconciledSourceSHA256 {
			return rb.Result{}, mw.ErrConflict
		}
	} else if result.Mode != "unchanged" {
		return rb.Result{}, mw.ErrConflict
	}
	if state != "planned" || v.State != "active" || v.Revision != input.ExpectedRevision || time.Since(planned) > 10*time.Minute || time.Until(planned) > time.Minute {
		return rb.Result{}, mw.ErrConflict
	}
	if e = rollbackHead03312(ctx, tx, v); e != nil {
		return rb.Result{}, e
	}
	// Always verify that baseline points to the same unchanged published release.
	if v.BaselineRevision > 0 {
		var releaseVersion, status string
		var baselineRaw []byte
		if e = tx.QueryRowContext(ctx, `SELECT version,status,manifest FROM release_versions WHERE id=$1 AND project_id=$2 AND profile_id=$3 AND channel=$4`, v.BaselineReleaseID, project, v.ProfileID, v.Channel).Scan(&releaseVersion, &status, &baselineRaw); e != nil || status != "published" || releaseVersion != v.BaselineVersion {
			return rb.Result{}, mw.ErrConflict
		}
		var manifest model.Manifest
		if json.Unmarshal(baselineRaw, &manifest) != nil || manifest.ProjectID != project || manifest.ProfileID != v.ProfileID || manifest.Channel != v.Channel || manifest.Version != releaseVersion {
			return rb.Result{}, mw.ErrConflict
		}
		digest, e := co.VerifyRelease(manifest, trusted)
		if e != nil || digest != v.BaselineDigest {
			return rb.Result{}, mw.ErrConflict
		}
	}
	if IsStableChannel0341(v.Channel) {
		token := stablePermitToken03411(ctx)
		if len(token) != 64 {
			return rb.Result{}, ErrStableRuntimeGate0341
		}
		if _, e = tx.ExecContext(ctx, `SELECT set_config('never.stable_gate_token',$1,true)`, token); e != nil {
			return rb.Result{}, e
		}
	}
	if _, e = tx.ExecContext(ctx, `SELECT set_config('never.migration_cutover_run',$1,true)`, run); e != nil {
		return rb.Result{}, e
	}
	if v.BaselineRevision == 0 {
		_, e = tx.ExecContext(ctx, `DELETE FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3 AND revision=$4`, project, v.ProfileID, v.Channel, *v.ActivatedRevision)
	} else {
		_, e = tx.ExecContext(ctx, `UPDATE channel_heads SET revision=revision+1,release_id=$4,version=$5,manifest_digest=$6,updated_at=now() WHERE project_id=$1 AND profile_id=$2 AND channel=$3 AND revision=$7`, project, v.ProfileID, v.Channel, v.BaselineReleaseID, v.BaselineVersion, v.BaselineDigest, *v.ActivatedRevision)
	}
	if e != nil {
		return rb.Result{}, e
	}
	var revision int64
	e = tx.QueryRowContext(ctx, `UPDATE migration_cutovers_03311 SET state='rolled_back',revision=revision+1,updated_at=now() WHERE run_id=$1 AND profile_id=$2 AND channel=$3 AND state='active' AND revision=$4 RETURNING revision`, run, v.ProfileID, v.Channel, input.ExpectedRevision).Scan(&revision)
	if e != nil {
		return rb.Result{}, e
	}
	result.State = "completed"
	raw, _ = json.Marshal(result)
	_, e = tx.ExecContext(ctx, `UPDATE migration_rollbacks_03312 SET state='completed',result=$4::jsonb,completed_at=now() WHERE run_id=$1 AND profile_id=$2 AND channel=$3`, run, v.ProfileID, v.Channel, string(raw))
	if e != nil {
		return rb.Result{}, e
	}
	if e = eventRollback03312(ctx, tx, run, "gravit_rollback_completed", result); e != nil {
		return rb.Result{}, e
	}
	if e = tx.Commit(); e != nil {
		return rb.Result{}, fmt.Errorf("rollback commit uncertain; GET before retry: %w", e)
	}
	return result, nil
}
func (r *SQLRepository) MigrationRollback03312(ctx context.Context, run, profile, channel string) (rb.Result, error) {
	if e := r.check(); e != nil {
		return rb.Result{}, e
	}
	var raw []byte
	e := r.db.QueryRowContext(ctx, `SELECT result FROM migration_rollbacks_03312 WHERE run_id=$1 AND profile_id=$2 AND channel=$3`, run, profile, channel).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return rb.Result{}, mw.ErrNotFound
	}
	if e != nil {
		return rb.Result{}, e
	}
	var result rb.Result
	e = json.Unmarshal(raw, &result)
	return result, e
}
func eventRollback03312(ctx context.Context, tx *sql.Tx, run, kind string, result rb.Result) error {
	var revision int64
	if e := tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, run).Scan(&revision); e != nil {
		return e
	}
	b, _ := json.Marshal(map[string]any{"profileId": result.ProfileID, "channel": result.Channel, "planSha256": result.PlanSHA256, "snapshotSha256": result.CurrentSnapshotSHA256, "state": result.State, "blockers": result.Blockers})
	_, e := tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,$2,'source_assessment',$3,$4::jsonb)`, run, kind, revision, string(b))
	return e
}

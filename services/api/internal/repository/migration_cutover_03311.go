package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	co "gitflic.ru/skif4er/launcher/services/api/internal/gravitcutover"
	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const cutoverFields03311 = `run_id,project_id,profile_id,channel,stage_id,release_id,release_version,target_digest,baseline_revision,baseline_release_id,baseline_version,baseline_digest,state,revision,activated_revision,fence_reference,fence_evidence_sha256`

func cutoverScan03311(s interface{ Scan(...any) error }) (co.Route, error) {
	var v co.Route
	var rev sql.NullInt64
	e := s.Scan(&v.RunID, &v.ProjectID, &v.ProfileID, &v.Channel, &v.StageID, &v.ReleaseID, &v.ReleaseVersion, &v.TargetDigest, &v.BaselineRevision, &v.BaselineReleaseID, &v.BaselineVersion, &v.BaselineDigest, &v.State, &v.Revision, &rev, &v.FenceReference, &v.FenceEvidenceSHA256)
	if errors.Is(e, sql.ErrNoRows) {
		return v, mw.ErrNotFound
	}
	if e != nil {
		return v, e
	}
	if rev.Valid {
		v.ActivatedRevision = &rev.Int64
	}
	return v, nil
}
func (r *SQLRepository) MigrationCutover03311(ctx context.Context, runID, profile, channel string) (co.Route, error) {
	if e := r.check(); e != nil {
		return co.Route{}, e
	}
	return cutoverScan03311(r.db.QueryRowContext(ctx, `SELECT `+cutoverFields03311+` FROM migration_cutovers_03311 WHERE run_id=$1 AND profile_id=$2 AND channel=$3`, runID, profile, channel))
}
func (r *SQLRepository) MigrationCutovers03311(ctx context.Context, runID string) ([]co.Route, error) {
	if e := r.check(); e != nil {
		return nil, e
	}
	rows, e := r.db.QueryContext(ctx, `SELECT `+cutoverFields03311+` FROM migration_cutovers_03311 WHERE run_id=$1 ORDER BY profile_id,channel`, runID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []co.Route{}
	for rows.Next() {
		v, e := cutoverScan03311(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// checkCutoverReadiness03311 must execute under a migration-run FOR UPDATE lock.
// MIG10 is re-evaluated on every transition; later failed rehearsals take
// precedence and invalidate a previous ready report.
func checkCutoverReadiness03311(ctx context.Context, tx *sql.Tx, runID, stageID, currentSourceDigest string) error {
	var raw []byte
	var recordedAt time.Time
	e := tx.QueryRowContext(ctx, `SELECT report,recorded_at FROM migration_rehearsals_03310 WHERE run_id=$1 ORDER BY recorded_at DESC,stage_id DESC LIMIT 1`, runID).Scan(&raw, &recordedAt)
	if e != nil || time.Since(recordedAt) > 2*time.Hour || time.Until(recordedAt) > time.Minute {
		return mw.ErrConflict
	}
	var rep gr.Report
	if json.Unmarshal(raw, &rep) != nil {
		return mw.ErrConflict
	}
	validated, e := gr.Evaluate(rep)
	if e != nil || !validated.Ready || rep.StageID != stageID || validated.CutoverAllowed || (currentSourceDigest != "" && rep.SourceSnapshotSHA256 != currentSourceDigest) {
		return mw.ErrConflict
	}
	var inventory string
	if tx.QueryRowContext(ctx, `SELECT manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, runID).Scan(&inventory) != nil || inventory != rep.SourceInventorySHA256 {
		return mw.ErrConflict
	}
	var identityCount, blocked int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER (WHERE i.status='blocked' OR
 (i.status='matched' AND (i.target_user_id IS NULL OR NOT EXISTS (
   SELECT 1 FROM minecraft_profiles mp WHERE mp.user_id=i.target_user_id AND mp.uuid=i.minecraft_uuid)))
 OR (i.status='pending_import' AND NOT EXISTS (
   SELECT 1 FROM migration_security_targets_0336 t JOIN minecraft_profiles mp ON mp.user_id=t.user_id
   WHERE t.run_id=i.run_id AND t.expected_uuid=i.minecraft_uuid AND t.expected_name=i.username AND mp.uuid=i.minecraft_uuid)))
 ) FROM migration_identity_rows_0334 i WHERE i.run_id=$1`, runID).Scan(&identityCount, &blocked) != nil || identityCount == 0 || blocked > 0 {
		return mw.ErrConflict
	}
	var modulesReady bool
	if tx.QueryRowContext(ctx, `SELECT COALESCE((report->>'ready')::boolean,false) AND jsonb_array_length(report->'blockers')=0 FROM migration_modules_0338 WHERE run_id=$1`, runID).Scan(&modulesReady) != nil || !modulesReady {
		return mw.ErrConflict
	}
	var secOK, authOK bool
	if tx.QueryRowContext(ctx, `SELECT COALESCE((report->>'verified')::boolean,false) FROM migration_security_resets_0336 WHERE run_id=$1`, runID).Scan(&secOK) != nil || !secOK {
		return mw.ErrConflict
	}
	if tx.QueryRowContext(ctx, `SELECT COALESCE((report->>'manualReset')::int,0)=0 AND COALESCE((report->>'dryRun')::boolean,true)=false AND jsonb_array_length(report->'rows')>0 FROM migration_auth_imports_0335 WHERE run_id=$1`, runID).Scan(&authOK) != nil || !authOK {
		return mw.ErrConflict
	}
	return nil
}

// readSignedRelease03311 rejects unsigned/self-signed/foreign and unreleased
// content, including a package belonging to a different migration workflow.
func readSignedRelease03311(ctx context.Context, tx *sql.Tx, runID, project string, s co.Stage, trusted ed25519.PublicKey) (string, string, error) {
	var ver, status string
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT version,status,manifest FROM release_versions WHERE id=$1 AND project_id=$2 AND profile_id=$3 AND channel=$4`, s.ReleaseID, project, s.ProfileID, s.Channel).Scan(&ver, &status, &raw)
	if e != nil || status != "published" {
		return "", "", mw.ErrConflict
	}
	var m model.Manifest
	if json.Unmarshal(raw, &m) != nil || m.ProjectID != project || m.ProfileID != s.ProfileID || m.Channel != s.Channel || m.Version != ver {
		return "", "", mw.ErrConflict
	}
	digest, e := co.VerifyRelease(m, trusted)
	if e != nil {
		return "", "", mw.ErrConflict
	}
	var receiptCount int
	e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_content_0337 c JOIN build_workspaces_0226 w ON w.id=c.workspace_id
 WHERE c.run_id=$1 AND c.profile_id=$2 AND w.project_id=$3 AND w.data->>'packageId'=$4
 AND w.data->>'state' IN ('staged','built')`, runID, s.ProfileID, project, s.ReleaseID).Scan(&receiptCount)
	if e != nil || receiptCount != 1 {
		return "", "", mw.ErrConflict
	}
	return ver, digest, nil
}

// StageMigrationCutover03311 performs *real* channel writer fencing. Existing
// published routes continue serving unchanged until activation. No Gravit
// server is contacted and no claim about its writer state is inferred.
func (r *SQLRepository) StageMigrationCutover03311(ctx context.Context, runID string, s co.Stage, trusted ed25519.PublicKey) (co.Route, error) {
	if e := r.check(); e != nil {
		return co.Route{}, e
	}
	if e := co.ValidateStage(s); e != nil {
		return co.Route{}, e
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return co.Route{}, e
	}
	defer tx.Rollback()
	var project, kind, status, step string
	e = tx.QueryRowContext(ctx, `SELECT project_id,source_kind,status,step FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&project, &kind, &status, &step)
	if errors.Is(e, sql.ErrNoRows) {
		return co.Route{}, mw.ErrNotFound
	}
	if e != nil {
		return co.Route{}, e
	}
	if kind != "gravit" || status != "prepared" || step != "source_assessment" {
		return co.Route{}, mw.ErrBusy
	}
	// A project lock is shared with ordinary release publication.
	var locked string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM projects WHERE id=$1 FOR UPDATE`, project).Scan(&locked); e != nil {
		return co.Route{}, e
	}
	if e = checkCutoverReadiness03311(ctx, tx, runID, s.StageID, ""); e != nil {
		return co.Route{}, e
	}
	ver, digest, e := readSignedRelease03311(ctx, tx, runID, project, s, trusted)
	if e != nil {
		return co.Route{}, e
	}
	var oldRevision int64
	var oldID, oldVer, oldDigest string
	e = tx.QueryRowContext(ctx, `SELECT revision,release_id,version,manifest_digest FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, project, s.ProfileID, s.Channel).Scan(&oldRevision, &oldID, &oldVer, &oldDigest)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return co.Route{}, e
	}
	if oldRevision != s.ExpectedHeadRevision {
		return co.Route{}, mw.ErrConflict
	}
	v, e := cutoverScan03311(tx.QueryRowContext(ctx, `SELECT `+cutoverFields03311+` FROM migration_cutovers_03311 WHERE project_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, project, s.ProfileID, s.Channel))
	if e == nil {
		if v.RunID != runID || v.StageID != s.StageID || v.ReleaseID != s.ReleaseID || v.BaselineRevision != s.ExpectedHeadRevision || v.State != "staged" {
			return co.Route{}, mw.ErrConflict
		}
		if e = tx.Commit(); e != nil {
			return co.Route{}, e
		}
		return v, nil
	}
	if !errors.Is(e, mw.ErrNotFound) {
		return co.Route{}, e
	}
	e = tx.QueryRowContext(ctx, `INSERT INTO migration_cutovers_03311(run_id,project_id,profile_id,channel,stage_id,release_id,release_version,target_digest,baseline_revision,baseline_release_id,baseline_version,baseline_digest)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+cutoverFields03311, runID, project, s.ProfileID, s.Channel, s.StageID, s.ReleaseID, ver, digest, oldRevision, oldID, oldVer, oldDigest).Scan(&v.RunID, &v.ProjectID, &v.ProfileID, &v.Channel, &v.StageID, &v.ReleaseID, &v.ReleaseVersion, &v.TargetDigest, &v.BaselineRevision, &v.BaselineReleaseID, &v.BaselineVersion, &v.BaselineDigest, &v.State, &v.Revision, new(sql.NullInt64), &v.FenceReference, &v.FenceEvidenceSHA256)
	if e != nil {
		return co.Route{}, e
	}
	if e = eventCutover03311(ctx, tx, runID, "gravit_cutover_staged", v); e != nil {
		return co.Route{}, e
	}
	if e = tx.Commit(); e != nil {
		return co.Route{}, fmt.Errorf("cutover stage commit uncertain; GET before retry: %w", e)
	}
	return v, nil
}
func eventCutover03311(ctx context.Context, tx *sql.Tx, runID, kind string, v co.Route) error {
	var rev int64
	e := tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, runID).Scan(&rev)
	if e != nil {
		return e
	}
	detail, _ := json.Marshal(map[string]any{"profileId": v.ProfileID, "channel": v.Channel, "releaseId": v.ReleaseID, "stageId": v.StageID, "routeState": v.State, "routeRevision": v.Revision, "headRevision": v.ActivatedRevision})
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,$2,'source_assessment',$3,$4::jsonb)`, runID, kind, rev, string(detail))
	return e
}

// ActivateMigrationCutover03311 atomically changes the actual Never delivery
// pointer. SourceFenceReference is an OPERATOR attestation (not independently
// proven by Never), retained to support MIG12 reconciliation and audit.
func (r *SQLRepository) ActivateMigrationCutover03311(ctx context.Context, runID string, a co.Activate, trusted ed25519.PublicKey) (co.Route, error) {
	if e := r.check(); e != nil {
		return co.Route{}, e
	}
	if e := co.ValidateActivation(a); e != nil {
		return co.Route{}, e
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return co.Route{}, e
	}
	defer tx.Rollback()
	var project, status, step string
	e = tx.QueryRowContext(ctx, `SELECT project_id,status,step FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&project, &status, &step)
	if errors.Is(e, sql.ErrNoRows) {
		return co.Route{}, mw.ErrNotFound
	}
	if e != nil {
		return co.Route{}, e
	}
	if status != "prepared" || step != "source_assessment" {
		return co.Route{}, mw.ErrBusy
	}
	var locked string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM projects WHERE id=$1 FOR UPDATE`, project).Scan(&locked); e != nil {
		return co.Route{}, e
	}
	v, e := cutoverScan03311(tx.QueryRowContext(ctx, `SELECT `+cutoverFields03311+` FROM migration_cutovers_03311 WHERE run_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, runID, a.ProfileID, a.Channel))
	if e != nil {
		return co.Route{}, e
	}
	if v.State == "active" {
		if v.FenceReference != a.SourceFenceReference || v.FenceEvidenceSHA256 != a.SourceFenceEvidenceSHA256 || v.Revision != a.ExpectedRevision+1 {
			return co.Route{}, mw.ErrConflict
		}
		if e = tx.Commit(); e != nil {
			return co.Route{}, e
		}
		return v, nil
	}
	if v.State != "staged" || v.Revision != a.ExpectedRevision {
		return co.Route{}, mw.ErrConflict
	}
	if e = checkCutoverReadiness03311(ctx, tx, runID, v.StageID, a.CurrentSourceSnapshotSHA256); e != nil {
		return co.Route{}, e
	}
	_, digest, e := readSignedRelease03311(ctx, tx, runID, project, co.Stage{ProfileID: v.ProfileID, Channel: v.Channel, ReleaseID: v.ReleaseID, ExpectedHeadRevision: v.BaselineRevision, StageID: v.StageID}, trusted)
	if e != nil || digest != v.TargetDigest {
		return co.Route{}, mw.ErrConflict
	}
	var current int64
	e = tx.QueryRowContext(ctx, `SELECT revision FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, project, v.ProfileID, v.Channel).Scan(&current)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return co.Route{}, e
	}
	if current != v.BaselineRevision {
		return co.Route{}, mw.ErrConflict
	}
	// The migration fence is not a runtime certification. For stable, a
	// separately verified, one-use permit is mandatory in this transaction.
	if IsStableChannel0341(v.Channel) {
		token := stablePermitToken03411(ctx)
		if len(token) != 64 {
			return co.Route{}, ErrStableRuntimeGate0341
		}
		if _, e = tx.ExecContext(ctx, `SELECT set_config('never.stable_gate_token',$1,true)`, token); e != nil {
			return co.Route{}, e
		}
	}
	// A SET LOCAL marker permits only this run's exact channel update through
	// the DB trigger. Stale workers/ordinary publication remain fenced.
	if _, e = tx.ExecContext(ctx, `SELECT set_config('never.migration_cutover_run',$1,true)`, runID); e != nil {
		return co.Route{}, e
	}
	if current == 0 {
		_, e = tx.ExecContext(ctx, `INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest) VALUES($1,$2,$3,1,$4,$5,$6)`, project, v.ProfileID, v.Channel, v.ReleaseID, v.ReleaseVersion, v.TargetDigest)
	} else {
		res, err := tx.ExecContext(ctx, `UPDATE channel_heads SET revision=revision+1,release_id=$4,version=$5,manifest_digest=$6,updated_at=now() WHERE project_id=$1 AND profile_id=$2 AND channel=$3 AND revision=$7`, project, v.ProfileID, v.Channel, v.ReleaseID, v.ReleaseVersion, v.TargetDigest, current)
		e = err
		if e == nil {
			var n int64
			n, e = res.RowsAffected()
			if e == nil && n != 1 {
				e = mw.ErrConflict
			}
		}
	}
	if e != nil {
		return co.Route{}, e
	}
	e = tx.QueryRowContext(ctx, `UPDATE migration_cutovers_03311 SET state='active',fence_reference=$5,fence_evidence_sha256=$6,activated_revision=$7,activated_at=now(),revision=revision+1,updated_at=now()
 WHERE run_id=$1 AND project_id=$2 AND profile_id=$3 AND channel=$4 AND state='staged' RETURNING `+cutoverFields03311, runID, project, a.ProfileID, a.Channel, a.SourceFenceReference, a.SourceFenceEvidenceSHA256, current+1).Scan(&v.RunID, &v.ProjectID, &v.ProfileID, &v.Channel, &v.StageID, &v.ReleaseID, &v.ReleaseVersion, &v.TargetDigest, &v.BaselineRevision, &v.BaselineReleaseID, &v.BaselineVersion, &v.BaselineDigest, &v.State, &v.Revision, new(sql.NullInt64), &v.FenceReference, &v.FenceEvidenceSHA256)
	if e != nil {
		return co.Route{}, e
	}
	rev := current + 1
	v.ActivatedRevision = &rev
	if e = eventCutover03311(ctx, tx, runID, "gravit_cutover_activated", v); e != nil {
		return co.Route{}, e
	}
	if e = tx.Commit(); e != nil {
		return co.Route{}, fmt.Errorf("cutover commit uncertain; GET before retry: %w", e)
	}
	return v, nil
}

// Cancel affects staged (unactivated) scopes ONLY. Post-switch reconciliation
// is MIG12; an old snapshot is never restored over live writes here.
func (r *SQLRepository) CancelMigrationCutover03311(ctx context.Context, runID, profile, channel string, expected int64) (co.Route, error) {
	if e := r.check(); e != nil {
		return co.Route{}, e
	}
	if expected < 1 {
		return co.Route{}, mw.ErrConflict
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return co.Route{}, e
	}
	defer tx.Rollback()
	var project string
	if e = tx.QueryRowContext(ctx, `SELECT project_id FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&project); e != nil {
		return co.Route{}, e
	}
	v, e := cutoverScan03311(tx.QueryRowContext(ctx, `SELECT `+cutoverFields03311+` FROM migration_cutovers_03311 WHERE run_id=$1 AND profile_id=$2 AND channel=$3 FOR UPDATE`, runID, profile, channel))
	if e != nil {
		return co.Route{}, e
	}
	if v.State != "staged" || v.Revision != expected {
		return co.Route{}, mw.ErrConflict
	}
	e = tx.QueryRowContext(ctx, `UPDATE migration_cutovers_03311 SET state='cancelled',revision=revision+1,updated_at=now() WHERE project_id=$1 AND profile_id=$2 AND channel=$3 RETURNING `+cutoverFields03311, project, profile, channel).Scan(&v.RunID, &v.ProjectID, &v.ProfileID, &v.Channel, &v.StageID, &v.ReleaseID, &v.ReleaseVersion, &v.TargetDigest, &v.BaselineRevision, &v.BaselineReleaseID, &v.BaselineVersion, &v.BaselineDigest, &v.State, &v.Revision, new(sql.NullInt64), &v.FenceReference, &v.FenceEvidenceSHA256)
	if e != nil {
		return co.Route{}, e
	}
	if e = eventCutover03311(ctx, tx, runID, "gravit_cutover_cancelled", v); e != nil {
		return co.Route{}, e
	}
	if e = tx.Commit(); e != nil {
		return co.Route{}, fmt.Errorf("cutover cancellation commit uncertain; GET before retry: %w", e)
	}
	return v, nil
}

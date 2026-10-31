package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func (r *SQLRepository) GetMigrationRehearsal03310(ctx context.Context, runID string) (gr.Report, error) {
	var report gr.Report
	if err := r.check(); err != nil {
		return report, err
	}
	var raw []byte
	e := r.db.QueryRowContext(ctx, `SELECT report FROM migration_rehearsals_03310 WHERE run_id=$1 ORDER BY recorded_at DESC,stage_id DESC LIMIT 1`, runID).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return report, mw.ErrNotFound
	}
	if e != nil {
		return report, e
	}
	e = json.Unmarshal(raw, &report)
	return report, e
}

// SaveMigrationRehearsal03310 binds external staging evidence to durable MIG03,
// MIG04, MIG05, MIG06, MIG07 and MIG08 receipts in the SAME transaction. A
// rerun with changed evidence cannot overwrite the first certified rehearsal.
func (r *SQLRepository) SaveMigrationRehearsal03310(ctx context.Context, runID string, input gr.Report) (gr.Report, error) {
	var empty gr.Report
	if err := r.check(); err != nil {
		return empty, err
	}
	if input.RunID != runID {
		return empty, mw.ErrConflict
	}
	v, err := gr.Evaluate(input)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return empty, err
	}
	if len(raw) > gr.MaxReportBytes {
		return empty, errors.New("rehearsal evidence too large")
	}
	digest := sha256.Sum256(raw)
	checksum := hex.EncodeToString(digest[:])
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	var project, kind, status, step string
	err = tx.QueryRowContext(ctx, `SELECT project_id,source_kind,status,step FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&project, &kind, &status, &step)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, mw.ErrNotFound
	}
	if err != nil {
		return empty, err
	}
	if kind != "gravit" || status != "prepared" || step != "source_assessment" {
		return empty, mw.ErrBusy
	}
	var inventory string
	err = tx.QueryRowContext(ctx, `SELECT manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, runID).Scan(&inventory)
	if err != nil {
		return empty, err
	}
	if inventory != v.SourceInventorySHA256 {
		return empty, mw.ErrConflict
	}
	// A blocker in module inspection or identity mapping is never overridden by
	// a staging probe, even one whose test executable returned success.
	var modulesReady bool
	err = tx.QueryRowContext(ctx, `SELECT COALESCE((report->>'ready')::boolean,false) AND jsonb_array_length(report->'blockers')=0 FROM migration_modules_0338 WHERE run_id=$1`, runID).Scan(&modulesReady)
	if err != nil {
		return empty, err
	}
	if !modulesReady {
		return empty, mw.ErrConflict
	}
	var blocked int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_identity_rows_0334 WHERE run_id=$1 AND status='blocked'`, runID).Scan(&blocked)
	if err != nil {
		return empty, err
	}
	if blocked != 0 {
		return empty, mw.ErrConflict
	}
	// Ensure the actual player UUID mapping matches the earlier imported source
	// mapping, not just two operator supplied staging files.
	rows, err := tx.QueryContext(ctx, `SELECT provider||':'||source_id,minecraft_uuid FROM migration_identity_rows_0334 WHERE run_id=$1 ORDER BY source_id`, runID)
	if err != nil {
		return empty, err
	}
	mapped := map[string]string{}
	for rows.Next() {
		var id, uuid string
		if err = rows.Scan(&id, &uuid); err != nil {
			break
		}
		if _, found := mapped[id]; found {
			err = mw.ErrConflict
			break
		}
		mapped[id] = uuid
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return empty, err
	}
	if len(mapped) == 0 || len(mapped) != len(v.Source.Players) {
		return empty, mw.ErrConflict
	}
	for _, p := range v.Source.Players {
		if mapped[p.SourceID] != p.UUID {
			return empty, mw.ErrConflict
		}
	}
	// Must have real imported account/security receipts and at least one staged
	// migrated workspace before accepting a rehearsal. Missing is NOT success.
	for _, table := range []string{"migration_auth_imports_0335", "migration_security_resets_0336", "migration_content_0337"} {
		var n int
		switch table {
		case "migration_auth_imports_0335":
			err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_auth_imports_0335 WHERE run_id=$1`, runID).Scan(&n)
		case "migration_security_resets_0336":
			err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_security_resets_0336 WHERE run_id=$1`, runID).Scan(&n)
		case "migration_content_0337":
			err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_content_0337 WHERE run_id=$1`, runID).Scan(&n)
		}
		if err != nil {
			return empty, err
		}
		if n == 0 {
			return empty, mw.ErrConflict
		}
	}
	// A reserved but incompletely staged workspace is not a rehearsable release.
	var incompletes int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_content_0337 c JOIN build_workspaces_0226 w ON w.id=c.workspace_id
 WHERE c.run_id=$1 AND (
  w.data->>'state' NOT IN ('staged','built')
  OR jsonb_array_length(w.data->'files') <> jsonb_array_length(c.report->'files')
  OR EXISTS (
   SELECT 1 FROM jsonb_array_elements(c.report->'files') expected
   WHERE NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(w.data->'files') staged
    WHERE staged->>'path'=expected->>'targetPath'
      AND staged->>'sha256'=expected->>'sha256'
      AND staged->>'size'=expected->>'size'
      AND staged->>'ownership'=expected->>'ownership'
   )
  )
 )`, runID).Scan(&incompletes)
	if err != nil {
		return empty, err
	}
	if incompletes > 0 {
		return empty, mw.ErrConflict
	}
	// Existing Never data may change between rehearsal and cutover; checking it
	// again remains mandatory in MIG11. Rehearsal never authorizes a cutover.
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT report_sha256 FROM migration_rehearsals_03310 WHERE run_id=$1 AND stage_id=$2`, runID, v.StageID).Scan(&previous)
	if err == nil {
		if previous != checksum {
			return empty, mw.ErrConflict
		}
		if err = tx.Commit(); err != nil {
			return empty, err
		}
		return v, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_rehearsals_03310(run_id,stage_id,inventory_sha256,report_sha256,report) VALUES($1,$2,$3,$4,$5::jsonb)`, runID, v.StageID, inventory, checksum, string(raw)); err != nil {
		return empty, err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, runID).Scan(&revision); err != nil {
		return empty, err
	}
	detail, _ := json.Marshal(map[string]any{"stageId": v.StageID, "reportSha256": checksum, "ready": v.Ready, "blockers": len(v.Blockers)})
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_rehearsal_checked','source_assessment',$2,$3::jsonb)`, runID, revision, string(detail)); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, fmt.Errorf("rehearsal commit uncertain; GET receipt before retry: %w", err)
	}
	return v, nil
}

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	gm "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitmodules"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

func (r *SQLRepository) GetMigrationModules0338(ctx context.Context, runID string) (gm.Report, error) {
	if err := r.check(); err != nil {
		return gm.Report{}, err
	}
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT report FROM migration_modules_0338 WHERE run_id=$1`, runID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return gm.Report{}, mw.ErrNotFound
	}
	if err != nil {
		return gm.Report{}, err
	}
	var v gm.Report
	err = json.Unmarshal(raw, &v)
	return v, err
}

// SaveMigrationModules0338 is immutable and replay-safe. The migration run row
// serializes assessment writes with every other migration stage.
func (r *SQLRepository) SaveMigrationModules0338(ctx context.Context, runID string, report gm.Report) (gm.Report, error) {
	if err := r.check(); err != nil {
		return gm.Report{}, err
	}
	if report.Format != gm.Format || len(report.SourceSHA256) != 64 || len(report.InventorySHA256) != 64 || report.CutoverAllowed || report.Ready != (len(report.Blockers) == 0) {
		return gm.Report{}, mw.ErrConflict
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return gm.Report{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return gm.Report{}, err
	}
	defer tx.Rollback()
	var status, step, kind, source, inventory string
	err = tx.QueryRowContext(ctx, `SELECT status,step,source_kind FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&status, &step, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return gm.Report{}, mw.ErrNotFound
	}
	if err != nil {
		return gm.Report{}, err
	}
	if status != "prepared" || step != "source_assessment" || kind != "gravit" {
		return gm.Report{}, mw.ErrBusy
	}
	err = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, runID).Scan(&source, &inventory)
	if err != nil {
		return gm.Report{}, err
	}
	if source != report.SourceSHA256 || inventory != report.InventorySHA256 {
		return gm.Report{}, mw.ErrConflict
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT report FROM migration_modules_0338 WHERE run_id=$1`, runID).Scan(&previous)
	if err == nil {
		if string(previous) != string(raw) { // JSONB canonical bytes differ in field ordering: compare parsed structures instead.
			var old gm.Report
			if json.Unmarshal(previous, &old) != nil || !reportsEqual0338(old, report) {
				return gm.Report{}, mw.ErrConflict
			}
		}
		if err = tx.Commit(); err != nil {
			return gm.Report{}, err
		}
		return report, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return gm.Report{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_modules_0338(run_id,source_sha256,inventory_sha256,report) VALUES($1,$2,$3,$4::jsonb)`, runID, source, inventory, string(raw)); err != nil {
		return gm.Report{}, err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, runID).Scan(&revision)
	if err != nil {
		return gm.Report{}, err
	}
	event, _ := json.Marshal(map[string]any{"sourceSha256": source, "modules": len(report.Modules), "wrappers": len(report.Wrappers), "blockers": len(report.Blockers)})
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_modules_reviewed','source_assessment',$2,$3::jsonb)`, runID, revision, string(event)); err != nil {
		return gm.Report{}, err
	}
	if err = tx.Commit(); err != nil {
		return gm.Report{}, fmt.Errorf("module assessment commit uncertain; retry same source: %w", err)
	}
	return report, nil
}
func reportsEqual0338(a, b gm.Report) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func (r *SQLRepository) GetMigrationWrapperEnrollment0338(ctx context.Context, runID, wrapperPath string) (serverID, fingerprint string, err error) {
	if err = r.check(); err != nil {
		return
	}
	err = r.db.QueryRowContext(ctx, `SELECT server_id,public_key_fingerprint FROM migration_wrapper_enrollments_0338 WHERE run_id=$1 AND wrapper_path=$2`, runID, wrapperPath).Scan(&serverID, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		err = mw.ErrNotFound
	}
	return
}

// Reserve migration enrollment before creating the ServerBridge node. The
// immutable intent prevents a retry from adopting unrelated pre-existing keys.
func (r *SQLRepository) RecordMigrationWrapperEnrollment0338(ctx context.Context, runID, wrapperPath, serverID, fingerprint string) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, step string
	if err = tx.QueryRowContext(ctx, `SELECT status,step FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&status, &step); err != nil {
		return err
	}
	if status != "prepared" || step != "source_assessment" {
		return mw.ErrBusy
	}
	// Same run and wrapper can only enroll one key/node, including on retry.
	res, err := tx.ExecContext(ctx, `INSERT INTO migration_wrapper_enrollments_0338(run_id,wrapper_path,server_id,public_key_fingerprint)
 VALUES($1,$2,$3,$4) ON CONFLICT(run_id,wrapper_path) DO UPDATE SET server_id=EXCLUDED.server_id
 WHERE migration_wrapper_enrollments_0338.server_id=EXCLUDED.server_id AND migration_wrapper_enrollments_0338.public_key_fingerprint=EXCLUDED.public_key_fingerprint`, runID, wrapperPath, serverID, fingerprint)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return mw.ErrConflict
	}
	return tx.Commit()
}

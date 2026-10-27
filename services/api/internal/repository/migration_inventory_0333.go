package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

func (r *SQLRepository) GetMigrationInventory0333(ctx context.Context, id string) (inv.Inventory, error) {
	if e := r.check(); e != nil {
		return inv.Inventory{}, e
	}
	var raw []byte
	e := r.db.QueryRowContext(ctx, `SELECT inventory FROM migration_source_inventory_0333 WHERE run_id=$1`, id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return inv.Inventory{}, mw.ErrNotFound
	}
	if e != nil {
		return inv.Inventory{}, e
	}
	var report inv.Inventory
	if e = json.Unmarshal(raw, &report); e != nil {
		return inv.Inventory{}, e
	}
	if _, e = report.Manifest(); e != nil {
		return inv.Inventory{}, e
	}
	return report, nil
}

// SaveMigrationInventory0333 serializes against all existing run transitions.
// It rejects inconsistent compatibility input; replays never duplicate events.
func (r *SQLRepository) SaveMigrationInventory0333(ctx context.Context, id string, report inv.Inventory) (inv.Inventory, error) {
	if e := r.check(); e != nil {
		return inv.Inventory{}, e
	}
	if report.Format != inv.Format || len(report.SourceSHA256) != 64 || len(report.Files) > inv.MaxFiles {
		return inv.Inventory{}, errors.New("invalid inventory")
	}
	if _, e := report.Manifest(); e != nil {
		return inv.Inventory{}, e
	}
	data, e := json.Marshal(report)
	if e != nil {
		return inv.Inventory{}, e
	}
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		return inv.Inventory{}, e
	}
	defer tx.Rollback()
	var status, step, kind string
	e = tx.QueryRowContext(ctx, `SELECT status,step,source_kind FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, id).Scan(&status, &step, &kind)
	if errors.Is(e, sql.ErrNoRows) {
		return inv.Inventory{}, mw.ErrNotFound
	}
	if e != nil {
		return inv.Inventory{}, e
	}
	if status != "prepared" || step != "source_assessment" || kind != "gravit" {
		return inv.Inventory{}, mw.ErrBusy
	}
	var compat string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256 FROM migration_compatibility_0332 WHERE run_id=$1`, id).Scan(&compat)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return inv.Inventory{}, e
	}
	if e == nil && compat != report.SourceSHA256 {
		return inv.Inventory{}, mw.ErrConflict
	}
	var previous []byte
	e = tx.QueryRowContext(ctx, `SELECT inventory FROM migration_source_inventory_0333 WHERE run_id=$1`, id).Scan(&previous)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return inv.Inventory{}, e
	}
	if e == nil {
		var prev inv.Inventory
		if e = json.Unmarshal(previous, &prev); e != nil {
			return inv.Inventory{}, e
		}
		if prev.SourceSHA256 == report.SourceSHA256 {
			if prev.ManifestSHA256 != report.ManifestSHA256 {
				return inv.Inventory{}, mw.ErrConflict
			}
			if e = tx.Commit(); e != nil {
				return inv.Inventory{}, e
			}
			return prev, nil
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_source_inventory_0333(run_id,source_sha256,manifest_sha256,inventory)
 VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(run_id) DO UPDATE SET source_sha256=EXCLUDED.source_sha256,
 manifest_sha256=EXCLUDED.manifest_sha256,inventory=EXCLUDED.inventory,inventoried_at=now()`, id, report.SourceSHA256, report.ManifestSHA256, string(data))
	if e != nil {
		return inv.Inventory{}, e
	}
	var revision int64
	e = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, id).Scan(&revision)
	if e != nil {
		return inv.Inventory{}, e
	}
	detail, _ := json.Marshal(map[string]any{"sourceSha256": report.SourceSHA256, "manifestSha256": report.ManifestSHA256, "files": report.SourceEntries, "totalBytes": report.TotalBytes})
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_source_inventoried','source_assessment',$2,$3::jsonb)`, id, revision, string(detail))
	if e != nil {
		return inv.Inventory{}, e
	}
	if e = tx.Commit(); e != nil {
		return inv.Inventory{}, fmt.Errorf("inventory commit uncertain; reread before retry: %w", e)
	}
	return report, nil
}

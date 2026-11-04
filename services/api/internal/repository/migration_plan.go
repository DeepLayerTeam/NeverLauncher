package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	gp "gitflic.ru/skif4er/launcher/services/api/internal/gravitplan"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func (r *SQLRepository) GetMigrationPlan0442(ctx context.Context, runID string) (gp.Plan, error) {
	if e := r.check(); e != nil {
		return gp.Plan{}, e
	}
	var raw []byte
	e := r.db.QueryRowContext(ctx, `SELECT plan FROM migration_plan_0442 WHERE run_id=$1`, runID).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return gp.Plan{}, mw.ErrNotFound
	}
	if e != nil {
		return gp.Plan{}, e
	}
	var p gp.Plan
	if e = json.Unmarshal(raw, &p); e != nil {
		return gp.Plan{}, e
	}
	if e = gp.Verify(p); e != nil {
		return gp.Plan{}, e
	}
	return p, nil
}

// SaveMigrationPlan0442 транзакционно закрепляет инвентаризацию источника и
// оценку совместимости. Повтор идентичного пробного запуска идемпотентен.
func (r *SQLRepository) SaveMigrationPlan0442(ctx context.Context, p gp.Plan) (gp.Plan, error) {
	if e := r.check(); e != nil {
		return gp.Plan{}, e
	}
	if e := gp.Verify(p); e != nil {
		return gp.Plan{}, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return gp.Plan{}, e
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return gp.Plan{}, e
	}
	defer tx.Rollback()
	var project, source, status, step string
	e = tx.QueryRowContext(ctx, `SELECT project_id,source_kind,status,step FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, p.RunID).Scan(&project, &source, &status, &step)
	if errors.Is(e, sql.ErrNoRows) {
		return gp.Plan{}, mw.ErrNotFound
	}
	if e != nil {
		return gp.Plan{}, e
	}
	if source != "gravit" || status != "prepared" || step != "source_assessment" || project != p.ProjectID {
		return gp.Plan{}, mw.ErrBusy
	}
	var invSHA, manifest, compatSHA string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, p.RunID).Scan(&invSHA, &manifest)
	if errors.Is(e, sql.ErrNoRows) {
		return gp.Plan{}, mw.ErrConflict
	}
	if e != nil {
		return gp.Plan{}, e
	}
	e = tx.QueryRowContext(ctx, `SELECT source_sha256 FROM migration_compatibility_0332 WHERE run_id=$1`, p.RunID).Scan(&compatSHA)
	if errors.Is(e, sql.ErrNoRows) {
		return gp.Plan{}, mw.ErrConflict
	}
	if e != nil {
		return gp.Plan{}, e
	}
	if invSHA != p.SourceSHA256 || compatSHA != p.SourceSHA256 || manifest != p.InventorySHA256 {
		return gp.Plan{}, mw.ErrConflict
	}
	var prevSHA string
	e = tx.QueryRowContext(ctx, `SELECT plan_sha256 FROM migration_plan_0442 WHERE run_id=$1`, p.RunID).Scan(&prevSHA)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return gp.Plan{}, e
	}
	if prevSHA == p.PlanSHA256 {
		if e = tx.Commit(); e != nil {
			return gp.Plan{}, e
		}
		return p, nil
	}
	// Не заменяйте молча план после начала импорта содержимого.
	var imported bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM migration_content_0337 WHERE run_id=$1)`, p.RunID).Scan(&imported)
	if e != nil {
		return gp.Plan{}, e
	}
	if imported {
		return gp.Plan{}, mw.ErrConflict
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_plan_0442(run_id,source_sha256,inventory_sha256,target_sha256,plan_sha256,plan) VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(run_id) DO UPDATE SET source_sha256=excluded.source_sha256,inventory_sha256=excluded.inventory_sha256,target_sha256=excluded.target_sha256,plan_sha256=excluded.plan_sha256,plan=excluded.plan,updated_at=now()`, p.RunID, p.SourceSHA256, p.InventorySHA256, p.TargetSHA256, p.PlanSHA256, string(raw))
	if e != nil {
		return gp.Plan{}, e
	}
	var revision int64
	e = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, p.RunID).Scan(&revision)
	if e != nil {
		return gp.Plan{}, e
	}
	detail, _ := json.Marshal(map[string]string{"planSha256": p.PlanSHA256, "sourceSha256": p.SourceSHA256, "targetSha256": p.TargetSHA256, "status": p.Status})
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_dry_run','source_assessment',$2,$3::jsonb)`, p.RunID, revision, string(detail))
	if e != nil {
		return gp.Plan{}, e
	}
	if e = tx.Commit(); e != nil {
		return gp.Plan{}, fmt.Errorf("migration plan commit uncertain; reread plan before retry: %w", e)
	}
	return p, nil
}

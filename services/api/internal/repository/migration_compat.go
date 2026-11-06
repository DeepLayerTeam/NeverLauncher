package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// GetMigrationCompatibility0332 читает только очищенный отчёт. Учётные данные
// конфигурации источника никогда не попадают в БД или журнал событий.
func (r *SQLRepository) GetMigrationCompatibility0332(ctx context.Context, runID string) (gd.Report, error) {
	if err := r.check(); err != nil {
		return gd.Report{}, err
	}
	var data []byte
	err := r.db.QueryRowContext(ctx, `SELECT report FROM migration_compatibility_0332 WHERE run_id=$1`, runID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return gd.Report{}, mw.ErrNotFound
	}
	if err != nil {
		return gd.Report{}, err
	}
	var report gd.Report
	err = json.Unmarshal(data, &report)
	return report, err
}

// SaveMigrationCompatibility0332 — сериализуемый переход состояния с журналированием
// событий. Повтор тех же байтов идемпотентен даже при потере ответа. Новое сканирование
// в том же запуске увеличивает ревизию и заменяет прежний отчёт.
func (r *SQLRepository) SaveMigrationCompatibility0332(ctx context.Context, runID string, report gd.Report) (gd.Report, error) {
	if err := r.check(); err != nil {
		return gd.Report{}, err
	}
	if report.Format != "launcher.gravit-compatibility.v1" || len(report.SourceSHA256) != 64 || report.CutoverAllowed {
		return gd.Report{}, errors.New("некорректная или небезопасная оценка совместимости")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return gd.Report{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return gd.Report{}, err
	}
	defer tx.Rollback()
	var status, step string
	err = tx.QueryRowContext(ctx, `SELECT status,step FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&status, &step)
	if errors.Is(err, sql.ErrNoRows) {
		return gd.Report{}, mw.ErrNotFound
	}
	if err != nil {
		return gd.Report{}, err
	}
	if status != "prepared" || step != "source_assessment" {
		return gd.Report{}, mw.ErrBusy
	}
	// Инвентаризированный источник закрепляет точно те же входные байты на всё
	// выполнение.
	var pinned string
	pinErr := tx.QueryRowContext(ctx, `SELECT source_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, runID).Scan(&pinned)
	if pinErr != nil && !errors.Is(pinErr, sql.ErrNoRows) {
		return gd.Report{}, pinErr
	}
	if pinErr == nil && pinned != report.SourceSHA256 {
		return gd.Report{}, mw.ErrConflict
	}
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT source_sha256 FROM migration_compatibility_0332 WHERE run_id=$1`, runID).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return gd.Report{}, err
	}
	if previous == report.SourceSHA256 {
		var saved []byte
		if err = tx.QueryRowContext(ctx, `SELECT report FROM migration_compatibility_0332 WHERE run_id=$1`, runID).Scan(&saved); err != nil {
			return gd.Report{}, err
		}
		var old gd.Report
		if err = json.Unmarshal(saved, &old); err != nil {
			return gd.Report{}, err
		}
		if old.ClaimedVersion != report.ClaimedVersion {
			return gd.Report{}, mw.ErrConflict
		}
		if err = tx.Commit(); err != nil {
			return gd.Report{}, err
		}
		return old, nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_compatibility_0332(run_id,source_sha256,report) VALUES($1,$2,$3::jsonb) ON CONFLICT(run_id) DO UPDATE SET source_sha256=EXCLUDED.source_sha256,report=EXCLUDED.report,assessed_at=now()`, runID, report.SourceSHA256, string(data)); err != nil {
		return gd.Report{}, err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, runID).Scan(&revision); err != nil {
		return gd.Report{}, err
	}
	// Событие содержит только хеш и готовность/классификацию, но не конфигурацию
	// источника.
	event, _ := json.Marshal(map[string]string{"sourceSha256": report.SourceSHA256, "status": report.Status, "versionStatus": report.VersionStatus})
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_compatibility_assessed','source_assessment',$2,$3::jsonb)`, runID, revision, string(event)); err != nil {
		return gd.Report{}, err
	}
	if err = tx.Commit(); err != nil {
		return gd.Report{}, fmt.Errorf("Сохранение оценки совместимости не подтверждено; прочитайте сохранённый результат перед повтором: %w", err)
	}
	return report, nil
}

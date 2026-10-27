package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

func migrationID0331() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const migrationColumns0331 = `id, project_id, source_kind, status, step, revision, fence, result, last_error, created_at, updated_at`

func scanMigration0331(s interface{ Scan(...any) error }) (mw.Run, error) {
	var v mw.Run
	var payload []byte
	err := s.Scan(&v.ID, &v.ProjectID, &v.SourceKind, &v.Status, &v.Step, &v.Revision, &v.Fence, &payload, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, mw.ErrNotFound
	}
	if err != nil {
		return v, err
	}
	v.Result = json.RawMessage(payload)
	return v, nil
}
func (r *SQLRepository) CreateMigration0331(ctx context.Context, projectID, sourceKind, key string) (mw.Run, error) {
	if err := r.check(); err != nil {
		return mw.Run{}, err
	}
	if sourceKind != "gravit" || len(key) < 8 || len(key) > 128 {
		return mw.Run{}, errors.New("invalid migration source or idempotency key")
	}
	id, err := migrationID0331()
	if err != nil {
		return mw.Run{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return mw.Run{}, err
	}
	defer tx.Rollback()
	created := false
	var result mw.Run
	result, err = scanMigration0331(tx.QueryRowContext(ctx, `
 INSERT INTO migration_runs_0331(id,project_id,idempotency_key,source_kind)
 VALUES($1,$2,$3,$4) ON CONFLICT(project_id,idempotency_key) DO NOTHING
 RETURNING `+migrationColumns0331, id, projectID, key, sourceKind))
	if errors.Is(err, mw.ErrNotFound) {
		result, err = scanMigration0331(tx.QueryRowContext(ctx, `SELECT `+migrationColumns0331+` FROM migration_runs_0331 WHERE project_id=$1 AND idempotency_key=$2`, projectID, key))
	} else if err == nil {
		created = true
	}
	if err != nil {
		return mw.Run{}, err
	}
	if created {
		if _, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision) VALUES($1,'created',$2,$3)`, result.ID, result.Step, result.Revision); err != nil {
			return mw.Run{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return mw.Run{}, fmt.Errorf("migration creation commit uncertain; retry with same key: %w", err)
	}
	return result, nil
}

func (r *SQLRepository) GetMigration0331(ctx context.Context, id string) (mw.Run, error) {
	if err := r.check(); err != nil {
		return mw.Run{}, err
	}
	return scanMigration0331(r.db.QueryRowContext(ctx, `SELECT `+migrationColumns0331+` FROM migration_runs_0331 WHERE id=$1`, id))
}
func (r *SQLRepository) ListMigrations0331(ctx context.Context, project string) ([]mw.Run, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+migrationColumns0331+` FROM migration_runs_0331 WHERE project_id=$1 ORDER BY created_at DESC,id DESC LIMIT 100`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mw.Run{}
	for rows.Next() {
		v, e := scanMigration0331(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (r *SQLRepository) ClaimMigration0331(ctx context.Context, id, owner string, ttl time.Duration) (mw.Lease, error) {
	if err := r.check(); err != nil {
		return mw.Lease{}, err
	}
	if owner == "" || ttl < time.Second || ttl > 2*time.Minute {
		return mw.Lease{}, errors.New("invalid lease parameters")
	}
	v, err := scanMigration0331(r.db.QueryRowContext(ctx, `
 UPDATE migration_runs_0331 SET lease_owner=$2,lease_until=now()+($3::bigint * interval '1 millisecond'),
 status='running',fence=fence+1,updated_at=now()
 WHERE id=$1 AND status IN ('pending','running') AND step IN ('target_check','target_inventory')
 AND (lease_until IS NULL OR lease_until<now())
 RETURNING `+migrationColumns0331, id, owner, ttl.Milliseconds()))
	if errors.Is(err, mw.ErrNotFound) {
		return mw.Lease{}, mw.ErrBusy
	}
	if err != nil {
		return mw.Lease{}, err
	}
	return mw.Lease{Run: v, Owner: owner, Fence: v.Fence}, nil
}
func nextStep0331(step string) (string, string, error) {
	switch step {
	case "target_check":
		return "target_inventory", "pending", nil
	case "target_inventory":
		return "source_assessment", "prepared", nil
	}
	return "", "", errors.New("unsupported migration step")
}
func (r *SQLRepository) CheckpointMigration0331(ctx context.Context, lease mw.Lease, step string, payload json.RawMessage) (mw.Run, error) {
	if err := r.check(); err != nil {
		return mw.Run{}, err
	}
	next, status, err := nextStep0331(step)
	if err != nil {
		return mw.Run{}, err
	}
	if step != lease.Run.Step || !json.Valid(payload) {
		return mw.Run{}, mw.ErrConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return mw.Run{}, err
	}
	defer tx.Rollback()
	v, err := scanMigration0331(tx.QueryRowContext(ctx, `
 UPDATE migration_runs_0331 SET step=$4,status=$5,revision=revision+1,
 result=jsonb_set(result,ARRAY[$6]::text[], $7::jsonb,true),
 lease_owner=NULL,lease_until=NULL,updated_at=now(),last_error=''
 WHERE id=$1 AND lease_owner=$2 AND fence=$3 AND step=$6 AND status='running' AND lease_until>now()
 RETURNING `+migrationColumns0331, lease.Run.ID, lease.Owner, lease.Fence, next, status, step, string(payload)))
	if errors.Is(err, mw.ErrNotFound) {
		return mw.Run{}, mw.ErrConflict
	}
	if err != nil {
		return mw.Run{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'checkpoint',$2,$3,$4::jsonb)`, v.ID, step, v.Revision, string(payload))
	if err != nil {
		return mw.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return mw.Run{}, fmt.Errorf("checkpoint commit uncertain; reread run before retry: %w", err)
	}
	return v, nil
}
func (r *SQLRepository) FailMigration0331(ctx context.Context, lease mw.Lease, reason string) (mw.Run, error) {
	if err := r.check(); err != nil {
		return mw.Run{}, err
	}
	if len(reason) > 2048 {
		reason = reason[:2048]
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return mw.Run{}, err
	}
	defer tx.Rollback()
	v, err := scanMigration0331(tx.QueryRowContext(ctx, `
 UPDATE migration_runs_0331 SET status='failed',last_error=$4,lease_owner=NULL,lease_until=NULL,
 revision=revision+1,updated_at=now() WHERE id=$1 AND lease_owner=$2 AND fence=$3 AND lease_until>now()
 RETURNING `+migrationColumns0331, lease.Run.ID, lease.Owner, lease.Fence, reason))
	if errors.Is(err, mw.ErrNotFound) {
		return mw.Run{}, mw.ErrConflict
	}
	if err != nil {
		return mw.Run{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'failed',$2,$3,$4::jsonb)`, v.ID, v.Step, v.Revision, string(mustJSON0331(map[string]string{"reason": reason})))
	if err != nil {
		return mw.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return mw.Run{}, err
	}
	return v, nil
}
func mustJSON0331(value any) json.RawMessage { b, _ := json.Marshal(value); return b }
func (r *SQLRepository) migrationTransition0331(ctx context.Context, id, from, to, kind string) (mw.Run, error) {
	if err := r.check(); err != nil {
		return mw.Run{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return mw.Run{}, err
	}
	defer tx.Rollback()
	v, err := scanMigration0331(tx.QueryRowContext(ctx, `
 UPDATE migration_runs_0331 SET status=$3,lease_owner=NULL,lease_until=NULL,fence=fence+1,
 revision=revision+1,updated_at=now() WHERE id=$1 AND status=$2 AND (lease_until IS NULL OR lease_until<now())
 RETURNING `+migrationColumns0331, id, from, to))
	if errors.Is(err, mw.ErrNotFound) {
		return mw.Run{}, mw.ErrConflict
	}
	if err != nil {
		return mw.Run{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision) VALUES($1,$2,$3,$4)`, v.ID, kind, v.Step, v.Revision)
	if err != nil {
		return mw.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return mw.Run{}, err
	}
	return v, nil
}
func (r *SQLRepository) PauseMigration0331(ctx context.Context, id string) (mw.Run, error) {
	for _, from := range []string{"pending", "failed", "running"} {
		v, err := r.migrationTransition0331(ctx, id, from, "paused", "paused")
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, mw.ErrConflict) {
			return v, err
		}
	}
	return mw.Run{}, mw.ErrConflict
}
func (r *SQLRepository) ResumeMigration0331(ctx context.Context, id string) (mw.Run, error) {
	for _, from := range []string{"paused", "failed"} {
		v, err := r.migrationTransition0331(ctx, id, from, "pending", "resumed")
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, mw.ErrConflict) {
			return v, err
		}
	}
	return mw.Run{}, mw.ErrConflict
}
func (r *SQLRepository) MigrationEvents0331(ctx context.Context, id string, after int64, limit int) ([]mw.Event, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		return nil, errors.New("invalid event limit")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT seq,kind,step,revision,detail,created_at FROM migration_events_0331 WHERE run_id=$1 AND seq>$2 ORDER BY seq LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []mw.Event{}
	for rows.Next() {
		var e mw.Event
		var detail []byte
		if err = rows.Scan(&e.Sequence, &e.Kind, &e.Step, &e.Revision, &detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Detail = detail
		result = append(result, e)
	}
	return result, rows.Err()
}

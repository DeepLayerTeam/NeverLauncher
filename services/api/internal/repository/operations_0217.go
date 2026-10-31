package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// OperationJournal extends durable jobs without weakening their lease fencing.
// Cancellation is only permitted before execution; running operations must not be
// reported cancelled while their external side effects may still be in progress.
type OperationJournal interface {
	FindOperationByKey(ctx context.Context, kind, actor, key string) (model.DurableJob, error)
	CompleteOperationJob(ctx context.Context, id, leaseToken string, result []byte) (model.DurableJob, error)
	CancelOperationJob(ctx context.Context, id, actor string) (model.DurableJob, error)
	RetryOperationJob(ctx context.Context, id string) (model.DurableJob, error)
	ListOperationAttempts(ctx context.Context, id string) ([]model.DurableJobAttempt, error)
}

func (r *SQLRepository) CompleteOperationJob(ctx context.Context, id, token string, result []byte) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DurableJob{}, err
	}
	defer tx.Rollback()
	j, err := scanDurableJob0213(tx.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return model.DurableJob{}, err
	}
	if j.Status != model.DurableJobStatusRunning || j.LeaseToken != token || !j.LeaseExpiresAt.After(time.Now().UTC()) {
		return model.DurableJob{}, ErrLeaseLost
	}
	if len(result) == 0 {
		result = []byte(`{}`)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status='succeeded',result=$3::jsonb,lease_owner='',lease_token='',lease_expires_at=NULL,updated_at=now(),completed_at=now() WHERE id=$1 AND lease_token=$2`, id, token, string(result)); err != nil {
		return model.DurableJob{}, err
	}
	if err = r.finishJobAttempt0213(ctx, tx, id, j.AttemptCount, "succeeded", ""); err != nil {
		return model.DurableJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.DurableJob{}, err
	}
	return r.GetDurableJob(ctx, id)
}
func (r *SQLRepository) CancelOperationJob(ctx context.Context, id, actor string) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DurableJob{}, err
	}
	defer tx.Rollback()
	j, err := scanDurableJob0213(tx.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableJob{}, ErrNotFound
	}
	if err != nil {
		return model.DurableJob{}, err
	}
	if j.Status != model.DurableJobStatusPending {
		return model.DurableJob{}, ErrImmutable
	}
	_, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status='failed',last_error=$2,updated_at=now(),completed_at=now() WHERE id=$1 AND status='pending'`, id, "cancelled-by:"+actor)
	if err != nil {
		return model.DurableJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.DurableJob{}, err
	}
	return r.GetDurableJob(ctx, id)
}
func (r *SQLRepository) RetryOperationJob(ctx context.Context, id string) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DurableJob{}, err
	}
	defer tx.Rollback()
	j, err := scanDurableJob0213(tx.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableJob{}, ErrNotFound
	}
	if err != nil {
		return model.DurableJob{}, err
	}
	if j.Status != model.DurableJobStatusFailed && j.Status != model.DurableJobStatusDead && j.Status != model.DurableJobStatusRevoked {
		return model.DurableJob{}, ErrImmutable
	}
	// Attempt IDs stay monotonic across retries: overwrite prior audit records.
	_, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status='pending',max_attempts=GREATEST(max_attempts,attempt_count+8),last_error='',result='{}'::jsonb,available_at=now(),completed_at=NULL,updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return model.DurableJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.DurableJob{}, err
	}
	return r.GetDurableJob(ctx, id)
}
func (r *SQLRepository) ListOperationAttempts(ctx context.Context, id string) ([]model.DurableJobAttempt, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,job_id,attempt,worker_id,lease_fence,started_at,finished_at,status,error FROM durable_job_attempts WHERE job_id=$1 ORDER BY attempt`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.DurableJobAttempt, 0)
	for rows.Next() {
		var a model.DurableJobAttempt
		var finished sql.NullTime
		if err = rows.Scan(&a.ID, &a.JobID, &a.Attempt, &a.WorkerID, &a.LeaseFence, &a.StartedAt, &finished, &a.Status, &a.Error); err != nil {
			return nil, err
		}
		if finished.Valid {
			a.FinishedAt = finished.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// FindOperationByKey returns a saved operation independent of the mutable
// current release state. This makes retries after a successful publish replay
// the recorded result rather than trying to revalidate an immutable release.
func (r *SQLRepository) FindOperationByKey(ctx context.Context, kind, actor, key string) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	row := r.db.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE kind=$1 AND actor_type='user' AND actor_id=$2 AND idempotency_key=$3`, kind, actor, key)
	j, err := scanDurableJob0213(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableJob{}, ErrNotFound
	}
	return j, err
}

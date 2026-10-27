package sqlitecore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

var (
	ErrDurableLeaseLost   = errors.New("sqlite durable: lease expired, revoked or superseded")
	ErrDurableLeaseBusy   = errors.New("sqlite durable: lease held by another owner")
	ErrDurableIdempotency = errors.New("sqlite durable: idempotency key reused with different operation")
	ErrDurableState       = errors.New("sqlite durable: illegal state transition")
)

func durableNS() int64 { return time.Now().UTC().UnixNano() }
func durableTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
func validDurableTTL(ttl time.Duration) bool { return ttl >= time.Second && ttl <= time.Hour }
func validRetryDelay(d time.Duration) bool   { return d >= 0 && d <= 7*24*time.Hour }
func durableHash(raw []byte) (string, error) {
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	if len(raw) > 1024*1024 || !json.Valid(raw) {
		return "", errors.New("durable payload must be valid JSON <=1MiB")
	}
	// Preserve exact JSON bytes: retries must supply the exact original payload.
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
func newLeaseToken() (string, error) {
	a, e := uid()
	if e != nil {
		return "", e
	}
	b, e := uid()
	return a + b, e
}
func durableFieldsNonempty(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == "" || len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return false
		}
	}
	return true
}

const jobColumns = `id,kind,actor_type,actor_id,action,project_id,resource_type,resource_id,idempotency_key,payload,payload_digest,status,lease_owner,lease_token,lease_fence,lease_expires_at,attempt_count,max_attempts,available_at,last_error,result,created_at,updated_at,completed_at`

func scanDurableJob(row interface{ Scan(...any) error }) (model.DurableJob, error) {
	var j model.DurableJob
	var payload, result string
	var available, expiry, created, updated, completed int64
	e := row.Scan(&j.ID, &j.Kind, &j.ActorType, &j.ActorID, &j.Action, &j.ProjectID, &j.ResourceType, &j.ResourceID, &j.IdempotencyKey, &payload, &j.PayloadDigest, &j.Status, &j.LeaseOwner, &j.LeaseToken, &j.LeaseFence, &expiry, &j.AttemptCount, &j.MaxAttempts, &available, &j.LastError, &result, &created, &updated, &completed)
	if e != nil {
		return j, notFound(e)
	}
	j.Payload = json.RawMessage(payload)
	j.Result = json.RawMessage(result)
	j.AvailableAt = durableTime(available)
	j.LeaseExpiresAt = durableTime(expiry)
	j.CreatedAt = durableTime(created)
	j.UpdatedAt = durableTime(updated)
	j.CompletedAt = durableTime(completed)
	return j, nil
}
func readJob(ctx context.Context, q sqlitedurable.Executor, id string) (model.DurableJob, error) {
	return scanDurableJob(q.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM durable_jobs WHERE id=?", id))
}
func (r *Repository) GetDurableJob(ctx context.Context, id string) (j model.DurableJob, e error) {
	e = r.store.Read(ctx, func(q sqlitedurable.Executor) error { j, e = readJob(ctx, q, id); return e })
	return
}

// EnqueueDurableJob persists an immutable idempotency scope before returning.
// Idempotency keys are never automatically deleted; retrying after a crash is safe.
func (r *Repository) EnqueueDurableJob(ctx context.Context, j model.DurableJob, _ time.Duration) (out model.DurableJob, created bool, err error) {
	if !durableFieldsNonempty(j.Kind, j.ActorType, j.ActorID, j.Action, j.ResourceType, j.ResourceID, j.IdempotencyKey) || (j.ProjectID != "" && !durableFieldsNonempty(j.ProjectID)) {
		return out, false, errors.New("durable job requires valid identity/action/resource/idempotency")
	}
	if j.MaxAttempts == 0 {
		j.MaxAttempts = 8
	}
	if j.MaxAttempts < 1 || j.MaxAttempts > 100 {
		return out, false, errors.New("maxAttempts must be 1..100")
	}
	if len(j.Payload) == 0 {
		j.Payload = []byte(`{}`)
	}
	digest, e := durableHash(j.Payload)
	if e != nil {
		return out, false, e
	}
	if j.ID == "" {
		j.ID, e = newID("job_")
		if e != nil {
			return out, false, e
		}
	}
	if !durableFieldsNonempty(j.ID) {
		return out, false, errors.New("invalid job id")
	}
	now := durableNS()
	available := now
	if !j.AvailableAt.IsZero() {
		available = j.AvailableAt.UnixNano()
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		existing, e := scanDurableJob(q.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM durable_jobs WHERE kind=? AND actor_type=? AND actor_id=? AND idempotency_key=?", j.Kind, j.ActorType, j.ActorID, j.IdempotencyKey))
		if e == nil {
			if existing.Action != j.Action || existing.ProjectID != j.ProjectID || existing.ResourceType != j.ResourceType || existing.ResourceID != j.ResourceID || existing.PayloadDigest != digest {
				return ErrDurableIdempotency
			}
			out = existing
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO durable_jobs(id,kind,actor_type,actor_id,action,project_id,resource_type,resource_id,idempotency_key,payload,payload_digest,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?)`, j.ID, j.Kind, j.ActorType, j.ActorID, j.Action, j.ProjectID, j.ResourceType, j.ResourceID, j.IdempotencyKey, string(j.Payload), digest, j.MaxAttempts, available, now, now)
		if e != nil {
			return conflict(e)
		}
		created = true
		out, e = readJob(ctx, q, j.ID)
		return e
	})
	return
}

// claimJob is called with the sole SQLite writer transaction. Each attempt
// increments its permanent fencing epoch and writes an append-only attempt.
func claimJob(ctx context.Context, q sqlitedurable.Executor, id, worker string, ttl time.Duration, now int64) (model.DurableJob, bool, error) {
	j, e := readJob(ctx, q, id)
	if e != nil {
		return j, false, e
	}
	if !((j.Status == "pending" && j.AvailableAt.UnixNano() <= now) || (j.Status == "running" && j.LeaseExpiresAt.UnixNano() <= now)) {
		return j, false, nil
	}
	if j.Status == "running" {
		res, e := q.ExecContext(ctx, `UPDATE durable_job_attempts SET status='expired',finished_at=?,error='worker lease expired' WHERE job_id=? AND attempt=? AND status='running'`, now, id, j.AttemptCount)
		if e != nil {
			return j, false, e
		}
		n, e := res.RowsAffected()
		if e != nil || n != 1 {
			return j, false, ErrDurableState
		}
	}
	if j.AttemptCount >= j.MaxAttempts {
		_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET status='dead',lease_owner='',lease_token='',lease_expires_at=0,completed_at=?,updated_at=?,last_error='max attempts exhausted' WHERE id=?`, now, now, id)
		return j, false, e
	}
	if j.LeaseFence == math.MaxInt64 {
		return j, false, errors.New("durable fencing overflow")
	}
	token, e := newLeaseToken()
	if e != nil {
		return j, false, e
	}
	_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET status='running',lease_owner=?,lease_token=?,lease_fence=lease_fence+1,lease_expires_at=?,attempt_count=attempt_count+1,updated_at=? WHERE id=?`, worker, token, now+int64(ttl), now, id)
	if e != nil {
		return j, false, e
	}
	_, e = q.ExecContext(ctx, `INSERT INTO durable_job_attempts(job_id,attempt,worker_id,lease_fence,started_at,status) VALUES(?,?,?,?,?,'running')`, id, j.AttemptCount+1, worker, j.LeaseFence+1, now)
	if e != nil {
		return j, false, e
	}
	j, e = readJob(ctx, q, id)
	return j, true, e
}
func (r *Repository) LeaseDurableJob(ctx context.Context, id, worker string, ttl time.Duration) (out model.DurableJob, err error) {
	if !durableFieldsNonempty(id, worker) || !validDurableTTL(ttl) {
		return out, errors.New("invalid job lease identity or duration (1s..1h)")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var claimed bool
		var e error
		out, claimed, e = claimJob(ctx, q, id, worker, ttl, durableNS())
		if e != nil {
			return e
		}
		if !claimed {
			return ErrDurableLeaseBusy
		}
		return nil
	})
	return
}
func (r *Repository) LeaseDurableJobs(ctx context.Context, kind, worker string, limit int, ttl time.Duration) (out []model.DurableJob, err error) {
	if !durableFieldsNonempty(worker) || (kind != "" && !durableFieldsNonempty(kind)) || limit < 1 || limit > 100 || !validDurableTTL(ttl) {
		return nil, errors.New("invalid claim arguments")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		query := `SELECT id FROM durable_jobs WHERE ((status='pending' AND available_at<=?) OR (status='running' AND lease_expires_at<=?))`
		args := []any{now, now}
		if kind != "" {
			query += ` AND kind=?`
			args = append(args, kind)
		}
		query += ` ORDER BY available_at,created_at,id LIMIT ?`
		args = append(args, limit*2+32)
		rows, e := q.QueryContext(ctx, query, args...)
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		e = errors.Join(e, rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for _, id := range ids {
			if len(out) >= limit {
				break
			}
			j, ok, e := claimJob(ctx, q, id, worker, ttl, now)
			if e != nil {
				return e
			}
			if ok {
				out = append(out, j)
			}
		}
		return nil
	})
	return
}
func validateJobOwnership(j model.DurableJob, token string, now int64) error {
	if token == "" || j.Status != "running" || j.LeaseToken != token || j.LeaseExpiresAt.UnixNano() <= now {
		return ErrDurableLeaseLost
	}
	return nil
}
func (r *Repository) RenewDurableJob(ctx context.Context, id, token string, ttl time.Duration) (out model.DurableJob, err error) {
	if !validDurableTTL(ttl) {
		return out, errors.New("invalid renewal ttl")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		j, e := readJob(ctx, q, id)
		if e != nil {
			return e
		}
		now := durableNS()
		if e = validateJobOwnership(j, token, now); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET lease_expires_at=?,updated_at=? WHERE id=?`, now+int64(ttl), now, id)
		if e != nil {
			return e
		}
		out, e = readJob(ctx, q, id)
		return e
	})
	return
}

// CompleteOperationJob never reports success for a stale or expired worker.
func (r *Repository) CompleteOperationJob(ctx context.Context, id, token string, result []byte) (out model.DurableJob, err error) {
	return r.CompleteJobWithOutbox(ctx, id, token, result, nil)
}

// CompleteJobWithOutbox commits both the job transition and events in one WAL
// transaction. Crash before commit -> neither visible; after commit -> both.
func (r *Repository) CompleteJobWithOutbox(ctx context.Context, id, token string, result []byte, events []model.DurableOutboxEvent) (out model.DurableJob, err error) {
	if len(result) == 0 {
		result = []byte(`{}`)
	}
	if _, err = durableHash(result); err != nil {
		return
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		j, e := readJob(ctx, q, id)
		if e != nil {
			return e
		}
		now := durableNS()
		if e = validateJobOwnership(j, token, now); e != nil {
			return e
		}
		for _, v := range events {
			if _, _, e = enqueueOutbox(ctx, q, v, now); e != nil {
				return e
			}
		}
		_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET status='succeeded',result=?,lease_owner='',lease_token='',lease_expires_at=0,updated_at=?,completed_at=? WHERE id=?`, string(result), now, now, id)
		if e != nil {
			return e
		}
		if e = finishAttempt(ctx, q, j, now, "succeeded", ""); e != nil {
			return e
		}
		out, e = readJob(ctx, q, id)
		return e
	})
	return
}
func finishAttempt(ctx context.Context, q sqlitedurable.Executor, j model.DurableJob, now int64, status, msg string) error {
	res, e := q.ExecContext(ctx, `UPDATE durable_job_attempts SET status=?,finished_at=?,error=? WHERE job_id=? AND attempt=? AND lease_fence=? AND status='running'`, status, now, msg, j.ID, j.AttemptCount, j.LeaseFence)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDurableState
	}
	return nil
}
func (r *Repository) FailDurableJob(ctx context.Context, id, token, reason string, retryAfter time.Duration) (out model.DurableJob, err error) {
	if !validRetryDelay(retryAfter) {
		return out, errors.New("retry delay out of range")
	}
	if len(reason) > 2048 {
		reason = reason[:2048]
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		j, e := readJob(ctx, q, id)
		if e != nil {
			return e
		}
		now := durableNS()
		if e = validateJobOwnership(j, token, now); e != nil {
			return e
		}
		status, attemptStatus, completed := "pending", "retry", int64(0)
		if j.AttemptCount >= j.MaxAttempts {
			status = "dead"
			attemptStatus = "dead"
			completed = now
		}
		_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET status=?,lease_owner='',lease_token='',lease_expires_at=0,available_at=?,last_error=?,updated_at=?,completed_at=? WHERE id=?`, status, now+int64(retryAfter), reason, now, completed, id)
		if e != nil {
			return e
		}
		if e = finishAttempt(ctx, q, j, now, attemptStatus, reason); e != nil {
			return e
		}
		out, e = readJob(ctx, q, id)
		return e
	})
	return
}
func (r *Repository) TerminateDurableJob(ctx context.Context, id, token, status, reason string) (out model.DurableJob, err error) {
	if status != "failed" && status != "revoked" && status != "dead" {
		return out, ErrDurableState
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		j, e := readJob(ctx, q, id)
		if e != nil {
			return e
		}
		now := durableNS()
		if e = validateJobOwnership(j, token, now); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET status=?,last_error=?,lease_owner='',lease_token='',lease_expires_at=0,updated_at=?,completed_at=? WHERE id=?`, status, reason, now, now, id)
		if e != nil {
			return e
		}
		if e = finishAttempt(ctx, q, j, now, "failed", reason); e != nil {
			return e
		}
		out, e = readJob(ctx, q, id)
		return e
	})
	return
}
func (r *Repository) ListOperationAttempts(ctx context.Context, id string) (out []model.DurableJobAttempt, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT id,job_id,attempt,worker_id,lease_fence,started_at,finished_at,status,error FROM durable_job_attempts WHERE job_id=? ORDER BY attempt`, id)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a model.DurableJobAttempt
			var start, finish int64
			if e = rows.Scan(&a.ID, &a.JobID, &a.Attempt, &a.WorkerID, &a.LeaseFence, &start, &finish, &a.Status, &a.Error); e != nil {
				return e
			}
			a.StartedAt = durableTime(start)
			a.FinishedAt = durableTime(finish)
			out = append(out, a)
		}
		return rows.Err()
	})
	return
}

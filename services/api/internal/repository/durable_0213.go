package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var ErrLeaseBusy = errors.New("durable scope lease busy")
var ErrLeaseLost = errors.New("durable lease lost")

// DurableControlPlane is implemented by repositories that can persist work,
// fencing leases, transactional publication and outbox delivery across process
// restarts. PostgreSQL and the deterministic in-memory test repository implement
// the same semantics; production uses PostgreSQL.
type DurableControlPlane interface {
	EnqueueDurableJob(ctx context.Context, job model.DurableJob, ttl time.Duration) (model.DurableJob, bool, error)
	GetDurableJob(ctx context.Context, id string) (model.DurableJob, error)
	LeaseDurableJob(ctx context.Context, id, worker string, ttl time.Duration) (model.DurableJob, error)
	LeaseDurableJobs(ctx context.Context, kind, worker string, limit int, ttl time.Duration) ([]model.DurableJob, error)
	FailDurableJob(ctx context.Context, id, leaseToken, workerErr string, retryAfter time.Duration) (model.DurableJob, error)
	TerminateDurableJob(ctx context.Context, id, leaseToken, terminalStatus, reason string) (model.DurableJob, error)
	AcquireDurableScopeLease(ctx context.Context, scopeKey, owner string, ttl time.Duration) (model.DurableScopeLease, error)
	RenewDurableScopeLease(ctx context.Context, scopeKey, leaseToken string, ttl time.Duration) (model.DurableScopeLease, error)
	ReleaseDurableScopeLease(ctx context.Context, scopeKey, leaseToken string) error
	CommitDurablePublish(ctx context.Context, commit model.DurablePublishCommit) (model.ReleaseVersion, error)
	ClaimOutboxEvents(ctx context.Context, worker string, limit int, ttl time.Duration) ([]model.DurableOutboxEvent, error)
	CompleteOutboxEvent(ctx context.Context, id, leaseToken string) error
	FailOutboxEvent(ctx context.Context, id, leaseToken, deliveryErr string, retryAfter time.Duration) error
	ConsumeDurableNonce(ctx context.Context, namespace, nonceHash, subjectID string, metadata map[string]any, expiresAt time.Time) error
}

func randomHex0213(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func durableJobIdempotencyScope0213(job model.DurableJob) string {
	return "job:" + job.Kind + ":" + job.ActorType + ":" + job.ActorID
}

func normalizeDurableJob0213(job model.DurableJob) (model.DurableJob, error) {
	now := time.Now().UTC()
	job.Kind = strings.TrimSpace(job.Kind)
	job.ActorType = strings.TrimSpace(job.ActorType)
	job.ActorID = strings.TrimSpace(job.ActorID)
	job.Action = strings.TrimSpace(job.Action)
	job.ProjectID = strings.TrimSpace(job.ProjectID)
	job.ResourceType = strings.TrimSpace(job.ResourceType)
	job.ResourceID = strings.TrimSpace(job.ResourceID)
	job.IdempotencyKey = strings.TrimSpace(job.IdempotencyKey)
	if job.Kind == "" || job.ActorType == "" || job.ActorID == "" || job.Action == "" || job.ResourceType == "" || job.ResourceID == "" || job.IdempotencyKey == "" {
		return model.DurableJob{}, errors.New("durable job identity/action/resource/idempotency fields are required")
	}
	if len(job.Payload) == 0 {
		job.Payload = json.RawMessage(`{}`)
	}
	var canonical any
	if err := json.Unmarshal(job.Payload, &canonical); err != nil {
		return model.DurableJob{}, fmt.Errorf("invalid durable job payload: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return model.DurableJob{}, err
	}
	job.Payload = payload
	digest := sha256.Sum256(payload)
	job.PayloadDigest = hex.EncodeToString(digest[:])
	if job.ID == "" {
		rnd, err := randomHex0213(16)
		if err != nil {
			return model.DurableJob{}, err
		}
		job.ID = "job_" + rnd
	}
	if job.Status == "" {
		job.Status = model.DurableJobStatusPending
	}
	if job.MaxAttempts <= 0 {
		job.MaxAttempts = 8
	}
	if job.AvailableAt.IsZero() {
		job.AvailableAt = now
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	return job, nil
}

func scanDurableJob0213(scanner interface{ Scan(dest ...any) error }) (model.DurableJob, error) {
	var j model.DurableJob
	var leaseExpiry, completed sql.NullTime
	var payload, result []byte
	err := scanner.Scan(&j.ID, &j.Kind, &j.ActorType, &j.ActorID, &j.Action, &j.ProjectID, &j.ResourceType, &j.ResourceID, &j.IdempotencyKey, &payload, &j.PayloadDigest, &j.Status, &j.LeaseOwner, &j.LeaseToken, &j.LeaseFence, &leaseExpiry, &j.AttemptCount, &j.MaxAttempts, &j.AvailableAt, &j.LastError, &result, &j.CreatedAt, &j.UpdatedAt, &completed)
	if err != nil {
		return model.DurableJob{}, err
	}
	j.Payload = append(json.RawMessage(nil), payload...)
	j.Result = append(json.RawMessage(nil), result...)
	if leaseExpiry.Valid {
		j.LeaseExpiresAt = leaseExpiry.Time
	}
	if completed.Valid {
		j.CompletedAt = completed.Time
	}
	return j, nil
}

const durableJobColumns0213 = `id,kind,actor_type,actor_id,action,project_id,resource_type,resource_id,idempotency_key,payload,payload_digest,status,lease_owner,lease_token,lease_fence,lease_expires_at,attempt_count,max_attempts,available_at,last_error,result,created_at,updated_at,completed_at`

func (r *SQLRepository) EnqueueDurableJob(ctx context.Context, job model.DurableJob, ttl time.Duration) (model.DurableJob, bool, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	job, err := normalizeDurableJob0213(job)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	defer tx.Rollback()

	// The explicit idempotency ledger prevents accidental re-use of a caller key
	// with different request bytes. The job's own unique key is a second guard.
	res, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(scope,idempotency_key,request_digest,status,response,created_at,updated_at,expires_at)
VALUES($1,$2,$3,'in-progress',$4::jsonb,now(),now(),$5)
ON CONFLICT(scope,idempotency_key) DO NOTHING`, durableJobIdempotencyScope0213(job), job.IdempotencyKey, job.PayloadDigest, `{"jobId":"`+job.ID+`"}`, time.Now().UTC().Add(ttl))
	if err != nil {
		return model.DurableJob{}, false, err
	}
	createdIdempotency, _ := res.RowsAffected()
	if createdIdempotency == 0 {
		var existingDigest string
		var response []byte
		if err := tx.QueryRowContext(ctx, `SELECT request_digest,response FROM idempotency_records WHERE scope=$1 AND idempotency_key=$2 FOR UPDATE`, durableJobIdempotencyScope0213(job), job.IdempotencyKey).Scan(&existingDigest, &response); err != nil {
			return model.DurableJob{}, false, err
		}
		if existingDigest != job.PayloadDigest {
			return model.DurableJob{}, false, ErrConflict
		}
		var ref struct {
			JobID string `json:"jobId"`
		}
		_ = json.Unmarshal(response, &ref)
		if ref.JobID == "" {
			return model.DurableJob{}, false, ErrConflict
		}
		existing, err := scanDurableJob0213(tx.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1`, ref.JobID))
		if err != nil {
			return model.DurableJob{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return model.DurableJob{}, false, err
		}
		return existing, false, nil
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO durable_jobs(`+durableJobColumns0213+`) VALUES(
$1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,'','',0,NULL,0,$13,$14,'','{}'::jsonb,$15,$16,NULL)`, job.ID, job.Kind, job.ActorType, job.ActorID, job.Action, job.ProjectID, job.ResourceType, job.ResourceID, job.IdempotencyKey, string(job.Payload), job.PayloadDigest, job.Status, job.MaxAttempts, job.AvailableAt, job.CreatedAt, job.UpdatedAt)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return model.DurableJob{}, false, err
	}
	return job, true, nil
}

func (r *SQLRepository) GetDurableJob(ctx context.Context, id string) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	j, err := scanDurableJob0213(r.db.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableJob{}, ErrNotFound
	}
	return j, err
}

func (r *SQLRepository) leaseDurableJobTx0213(ctx context.Context, tx *sql.Tx, id, worker string, ttl time.Duration) (model.DurableJob, error) {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if strings.TrimSpace(worker) == "" {
		return model.DurableJob{}, errors.New("worker id required")
	}
	var current model.DurableJob
	var err error
	if id != "" {
		current, err = scanDurableJob0213(tx.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1 FOR UPDATE`, id))
	} else {
		return model.DurableJob{}, errors.New("job id required")
	}
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableJob{}, ErrNotFound
	}
	if err != nil {
		return model.DurableJob{}, err
	}
	now := time.Now().UTC()
	if current.Status == model.DurableJobStatusSucceeded || current.Status == model.DurableJobStatusRevoked || current.Status == model.DurableJobStatusDead || current.Status == model.DurableJobStatusFailed {
		return current, ErrImmutable
	}
	if current.Status == model.DurableJobStatusRunning && current.LeaseExpiresAt.After(now) {
		return current, ErrLeaseBusy
	}
	if current.Status == model.DurableJobStatusRunning && !current.LeaseExpiresAt.After(now) && current.AttemptCount > 0 {
		// Close the abandoned attempt before fencing a replacement worker. Leaving
		// it marked running would make restart recovery operationally ambiguous.
		if _, err := tx.ExecContext(ctx, `UPDATE durable_job_attempts SET status='failed',error='lease expired; recovered by another worker',finished_at=$3 WHERE job_id=$1 AND attempt=$2 AND status='running'`, current.ID, current.AttemptCount, now); err != nil {
			return model.DurableJob{}, err
		}
	}
	if current.AvailableAt.After(now) {
		return current, ErrLeaseBusy
	}
	if current.AttemptCount >= current.MaxAttempts {
		_, _ = tx.ExecContext(ctx, `UPDATE durable_jobs SET status='dead',last_error='max attempts exceeded',updated_at=now(),completed_at=now(),lease_owner='',lease_token='',lease_expires_at=NULL WHERE id=$1`, current.ID)
		return current, ErrImmutable
	}
	token, err := randomHex0213(24)
	if err != nil {
		return model.DurableJob{}, err
	}
	current.AttemptCount++
	current.LeaseFence++
	current.Status = model.DurableJobStatusRunning
	current.LeaseOwner = worker
	current.LeaseToken = token
	current.LeaseExpiresAt = now.Add(ttl)
	current.UpdatedAt = now
	_, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status='running',lease_owner=$2,lease_token=$3,lease_fence=$4,lease_expires_at=$5,attempt_count=$6,updated_at=$7,last_error='' WHERE id=$1`, current.ID, worker, token, current.LeaseFence, current.LeaseExpiresAt, current.AttemptCount, now)
	if err != nil {
		return model.DurableJob{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO durable_job_attempts(job_id,attempt,worker_id,lease_fence,started_at,status) VALUES($1,$2,$3,$4,$5,'running')`, current.ID, current.AttemptCount, worker, current.LeaseFence, now)
	if err != nil {
		return model.DurableJob{}, err
	}
	return current, nil
}

func (r *SQLRepository) LeaseDurableJob(ctx context.Context, id, worker string, ttl time.Duration) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DurableJob{}, err
	}
	defer tx.Rollback()
	j, err := r.leaseDurableJobTx0213(ctx, tx, strings.TrimSpace(id), strings.TrimSpace(worker), ttl)
	if err != nil {
		return j, err
	}
	if err := tx.Commit(); err != nil {
		return model.DurableJob{}, err
	}
	return j, nil
}

func (r *SQLRepository) LeaseDurableJobs(ctx context.Context, kind, worker string, limit int, ttl time.Duration) ([]model.DurableJob, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = 16
	}
	if limit > 100 {
		limit = 100
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM durable_jobs
WHERE kind=$1 AND ((status='pending' AND available_at<=now()) OR (status='running' AND lease_expires_at<=now())) AND attempt_count < max_attempts
ORDER BY available_at,created_at FOR UPDATE SKIP LOCKED LIMIT $2`, strings.TrimSpace(kind), limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]model.DurableJob, 0, len(ids))
	for _, id := range ids {
		j, err := r.leaseDurableJobTx0213(ctx, tx, id, worker, ttl)
		if err != nil {
			if errors.Is(err, ErrLeaseBusy) || errors.Is(err, ErrImmutable) {
				continue
			}
			return nil, err
		}
		out = append(out, j)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *SQLRepository) finishJobAttempt0213(ctx context.Context, tx *sql.Tx, jobID string, attempt int, status, message string) error {
	_, err := tx.ExecContext(ctx, `UPDATE durable_job_attempts SET status=$3,error=$4,finished_at=now() WHERE job_id=$1 AND attempt=$2 AND status='running'`, jobID, attempt, status, message)
	return err
}

func (r *SQLRepository) FailDurableJob(ctx context.Context, id, leaseToken, workerErr string, retryAfter time.Duration) (model.DurableJob, error) {
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if retryAfter < 0 {
		retryAfter = 0
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
	if j.Status != model.DurableJobStatusRunning || j.LeaseToken != leaseToken {
		return model.DurableJob{}, ErrLeaseLost
	}
	status := model.DurableJobStatusPending
	completed := false
	if j.AttemptCount >= j.MaxAttempts {
		status = model.DurableJobStatusDead
		completed = true
	}
	completedAt := any(nil)
	if completed {
		completedAt = time.Now().UTC()
	}
	_, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status=$2,lease_owner='',lease_token='',lease_expires_at=NULL,available_at=$3,last_error=$4,updated_at=now(),completed_at=$5 WHERE id=$1 AND lease_token=$6`, id, status, time.Now().UTC().Add(retryAfter), workerErr, completedAt, leaseToken)
	if err != nil {
		return model.DurableJob{}, err
	}
	attemptStatus := "failed"
	if status == model.DurableJobStatusDead {
		attemptStatus = "dead"
	}
	if err := r.finishJobAttempt0213(ctx, tx, id, j.AttemptCount, attemptStatus, workerErr); err != nil {
		return model.DurableJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.DurableJob{}, err
	}
	return r.GetDurableJob(ctx, id)
}

func (r *SQLRepository) TerminateDurableJob(ctx context.Context, id, leaseToken, terminalStatus, reason string) (model.DurableJob, error) {
	if terminalStatus != model.DurableJobStatusRevoked && terminalStatus != model.DurableJobStatusFailed && terminalStatus != model.DurableJobStatusDead {
		return model.DurableJob{}, errors.New("invalid terminal job status")
	}
	if err := r.check(); err != nil {
		return model.DurableJob{}, err
	}
	if ctx == nil {
		ctx = context.Background()
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
	if j.Status != model.DurableJobStatusRunning || j.LeaseToken != leaseToken {
		return model.DurableJob{}, ErrLeaseLost
	}
	_, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status=$2,lease_owner='',lease_token='',lease_expires_at=NULL,last_error=$3,updated_at=now(),completed_at=now() WHERE id=$1 AND lease_token=$4`, id, terminalStatus, reason, leaseToken)
	if err != nil {
		return model.DurableJob{}, err
	}
	if err := r.finishJobAttempt0213(ctx, tx, id, j.AttemptCount, terminalStatus, reason); err != nil {
		return model.DurableJob{}, err
	}
	_, _ = tx.ExecContext(ctx, `UPDATE idempotency_records SET status='failed',response=jsonb_build_object('jobId',$3,'status',$4,'error',$5),updated_at=now() WHERE scope=$1 AND idempotency_key=$2`, durableJobIdempotencyScope0213(j), j.IdempotencyKey, j.ID, terminalStatus, reason)
	if err := tx.Commit(); err != nil {
		return model.DurableJob{}, err
	}
	return r.GetDurableJob(ctx, id)
}

func (r *SQLRepository) AcquireDurableScopeLease(ctx context.Context, scopeKey, owner string, ttl time.Duration) (model.DurableScopeLease, error) {
	if err := r.check(); err != nil {
		return model.DurableScopeLease{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	scopeKey, owner = strings.TrimSpace(scopeKey), strings.TrimSpace(owner)
	if scopeKey == "" || owner == "" {
		return model.DurableScopeLease{}, errors.New("scope key and owner required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	token, err := randomHex0213(24)
	if err != nil {
		return model.DurableScopeLease{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	var lease model.DurableScopeLease
	err = r.db.QueryRowContext(ctx, `INSERT INTO durable_scope_leases(scope_key,owner,lease_token,fencing_token,expires_at,updated_at)
VALUES($1,$2,$3,1,$4,$5)
ON CONFLICT(scope_key) DO UPDATE SET owner=EXCLUDED.owner,lease_token=EXCLUDED.lease_token,fencing_token=durable_scope_leases.fencing_token+1,expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at
WHERE durable_scope_leases.expires_at<=now()
RETURNING scope_key,owner,lease_token,fencing_token,expires_at,updated_at`, scopeKey, owner, token, expires, now).Scan(&lease.ScopeKey, &lease.Owner, &lease.LeaseToken, &lease.FencingToken, &lease.ExpiresAt, &lease.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableScopeLease{}, ErrLeaseBusy
	}
	return lease, err
}

func (r *SQLRepository) RenewDurableScopeLease(ctx context.Context, scopeKey, leaseToken string, ttl time.Duration) (model.DurableScopeLease, error) {
	if err := r.check(); err != nil {
		return model.DurableScopeLease{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	var lease model.DurableScopeLease
	err := r.db.QueryRowContext(ctx, `UPDATE durable_scope_leases SET expires_at=$3,updated_at=$4 WHERE scope_key=$1 AND lease_token=$2 AND expires_at>now() RETURNING scope_key,owner,lease_token,fencing_token,expires_at,updated_at`, strings.TrimSpace(scopeKey), strings.TrimSpace(leaseToken), now.Add(ttl), now).Scan(&lease.ScopeKey, &lease.Owner, &lease.LeaseToken, &lease.FencingToken, &lease.ExpiresAt, &lease.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DurableScopeLease{}, ErrLeaseLost
	}
	return lease, err
}

func (r *SQLRepository) ReleaseDurableScopeLease(ctx context.Context, scopeKey, leaseToken string) error {
	if err := r.check(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := r.db.ExecContext(ctx, `UPDATE durable_scope_leases SET expires_at=now(),updated_at=now() WHERE scope_key=$1 AND lease_token=$2`, strings.TrimSpace(scopeKey), strings.TrimSpace(leaseToken))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (r *SQLRepository) CommitDurablePublish(ctx context.Context, commit model.DurablePublishCommit) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	defer tx.Rollback()
	job, err := scanDurableJob0213(tx.QueryRowContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE id=$1 FOR UPDATE`, commit.JobID))
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if job.Status != model.DurableJobStatusRunning || job.LeaseToken != commit.JobLeaseToken || time.Now().UTC().After(job.LeaseExpiresAt) {
		return model.ReleaseVersion{}, ErrLeaseLost
	}
	var leaseOwner, scopeToken string
	var scopeFence int64
	var scopeExpiry time.Time
	if err := tx.QueryRowContext(ctx, `SELECT owner,lease_token,fencing_token,expires_at FROM durable_scope_leases WHERE scope_key=$1 FOR UPDATE`, commit.ScopeKey).Scan(&leaseOwner, &scopeToken, &scopeFence, &scopeExpiry); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ReleaseVersion{}, ErrLeaseLost
		}
		return model.ReleaseVersion{}, err
	}
	_ = leaseOwner
	if scopeToken != commit.ScopeLeaseToken || scopeFence != commit.ScopeFencingToken || time.Now().UTC().After(scopeExpiry) {
		return model.ReleaseVersion{}, ErrLeaseLost
	}

	var rel model.ReleaseVersion
	var manifestRaw []byte
	var published sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,project_id,profile_id,channel,version,status,manifest,published_at FROM release_versions WHERE id=$1 AND project_id=$2 FOR UPDATE`, job.ResourceID, job.ProjectID).Scan(&rel.ID, &rel.ProjectID, &rel.ProfileID, &rel.Channel, &rel.Version, &rel.Status, &manifestRaw, &published)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ReleaseVersion{}, ErrNotFound
	}
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if rel.Status == "published" {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if strings.TrimSpace(commit.ExpectedStatus) == "" || rel.Status != commit.ExpectedStatus {
		return model.ReleaseVersion{}, ErrConflict
	}
	if err := json.Unmarshal(manifestRaw, &rel.Manifest); err != nil {
		return model.ReleaseVersion{}, err
	}
	canonical, err := json.Marshal(rel.Manifest)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	manifestSum := sha256.Sum256(canonical)
	if hex.EncodeToString(manifestSum[:]) != strings.ToLower(strings.TrimSpace(commit.ExpectedManifestDigest)) {
		return model.ReleaseVersion{}, ErrConflict
	}
	var integrityManifest, integrityArtifact, integrityResult string
	err = tx.QueryRowContext(ctx, `SELECT manifest_digest,artifact_digest,result FROM package_integrity_checks WHERE package_id=$1 ORDER BY checked_at DESC,id DESC LIMIT 1`, rel.ID).Scan(&integrityManifest, &integrityArtifact, &integrityResult)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ReleaseVersion{}, ErrConflict
		}
		return model.ReleaseVersion{}, err
	}
	if integrityResult != "passed" || integrityManifest != commit.ExpectedManifestDigest || integrityArtifact != commit.ExpectedArtifactDigest {
		return model.ReleaseVersion{}, ErrConflict
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `UPDATE release_versions SET status='published',published_at=$2,updated_at=$2 WHERE id=$1 AND status=$4 AND manifest=$3::jsonb`, rel.ID, now, string(canonical), commit.ExpectedStatus)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.ReleaseVersion{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO release_channels(id,project_id,name,description,protected) VALUES($1,$2,$1,'Канал релиза',$3) ON CONFLICT(project_id,id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,protected=EXCLUDED.protected`, rel.Channel, rel.ProjectID, rel.Channel == "stable"); err != nil {
		return model.ReleaseVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,created_at) VALUES($1,$2,'package:publish',$3,$4)`, fmt.Sprintf("audit-%d", now.UnixNano()), commit.ActorID, rel.ID, now); err != nil {
		return model.ReleaseVersion{}, err
	}

	payload := map[string]any{"packageId": rel.ID, "projectId": rel.ProjectID, "profileId": rel.ProfileID, "channel": rel.Channel, "version": rel.Version, "status": "published", "actorId": commit.ActorID}
	payloadRaw, _ := json.Marshal(payload)
	for _, eventType := range []string{"package.published", "release.published"} {
		idSuffix, err := randomHex0213(10)
		if err != nil {
			return model.ReleaseVersion{}, err
		}
		idempotency := "publish:" + rel.ID + ":" + commit.ExpectedManifestDigest + ":" + eventType
		if _, err := tx.ExecContext(ctx, `INSERT INTO event_outbox(id,event_type,project_id,aggregate_type,aggregate_id,actor_id,idempotency_key,payload,status,max_attempts,available_at,created_at,updated_at) VALUES($1,$2,$3,'release',$4,$5,$6,$7::jsonb,'pending',12,$8,$8,$8) ON CONFLICT(idempotency_key) DO NOTHING`, "out_"+idSuffix, eventType, rel.ProjectID, rel.ID, commit.ActorID, idempotency, string(payloadRaw), now); err != nil {
			return model.ReleaseVersion{}, err
		}
	}
	resultRaw, _ := json.Marshal(map[string]any{"releaseId": rel.ID, "status": "published", "publishedAt": now})
	res, err = tx.ExecContext(ctx, `UPDATE durable_jobs SET status='succeeded',result=$2::jsonb,lease_owner='',lease_token='',lease_expires_at=NULL,last_error='',updated_at=$3,completed_at=$3 WHERE id=$1 AND lease_token=$4 AND status='running'`, job.ID, string(resultRaw), now, commit.JobLeaseToken)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.ReleaseVersion{}, ErrLeaseLost
	}
	if err := r.finishJobAttempt0213(ctx, tx, job.ID, job.AttemptCount, "succeeded", ""); err != nil {
		return model.ReleaseVersion{}, err
	}
	_, _ = tx.ExecContext(ctx, `UPDATE idempotency_records SET status='completed',response=$3::jsonb,updated_at=$4 WHERE scope=$1 AND idempotency_key=$2`, durableJobIdempotencyScope0213(job), job.IdempotencyKey, string(resultRaw), now)
	if err := tx.Commit(); err != nil {
		return model.ReleaseVersion{}, err
	}
	rel.Status = "published"
	rel.PublishedAt = now
	return rel, nil
}

func scanOutbox0213(scanner interface{ Scan(dest ...any) error }) (model.DurableOutboxEvent, error) {
	var e model.DurableOutboxEvent
	var payload []byte
	var leaseExpiry, delivered sql.NullTime
	err := scanner.Scan(&e.ID, &e.EventType, &e.ProjectID, &e.AggregateType, &e.AggregateID, &e.ActorID, &e.IdempotencyKey, &payload, &e.Status, &e.LeaseOwner, &e.LeaseToken, &e.LeaseFence, &leaseExpiry, &e.AttemptCount, &e.MaxAttempts, &e.AvailableAt, &e.LastError, &e.CreatedAt, &e.UpdatedAt, &delivered)
	if err != nil {
		return model.DurableOutboxEvent{}, err
	}
	e.Payload = append(json.RawMessage(nil), payload...)
	if leaseExpiry.Valid {
		e.LeaseExpiresAt = leaseExpiry.Time
	}
	if delivered.Valid {
		e.DeliveredAt = delivered.Time
	}
	return e, nil
}

const outboxColumns0213 = `id,event_type,project_id,aggregate_type,aggregate_id,actor_id,idempotency_key,payload,status,lease_owner,lease_token,lease_fence,lease_expires_at,attempt_count,max_attempts,available_at,last_error,created_at,updated_at,delivered_at`

func (r *SQLRepository) ClaimOutboxEvents(ctx context.Context, worker string, limit int, ttl time.Duration) ([]model.DurableOutboxEvent, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = 32
	}
	if limit > 100 {
		limit = 100
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM event_outbox WHERE ((status='pending' AND available_at<=now()) OR (status='running' AND lease_expires_at<=now())) AND attempt_count<max_attempts ORDER BY available_at,created_at FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := make([]model.DurableOutboxEvent, 0, len(ids))
	for _, id := range ids {
		token, err := randomHex0213(24)
		if err != nil {
			return nil, err
		}
		var e model.DurableOutboxEvent
		e, err = scanOutbox0213(tx.QueryRowContext(ctx, `UPDATE event_outbox SET status='running',lease_owner=$2,lease_token=$3,lease_fence=lease_fence+1,lease_expires_at=$4,attempt_count=attempt_count+1,updated_at=now() WHERE id=$1 RETURNING `+outboxColumns0213, id, worker, token, time.Now().UTC().Add(ttl)))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *SQLRepository) CompleteOutboxEvent(ctx context.Context, id, leaseToken string) error {
	if err := r.check(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := r.db.ExecContext(ctx, `UPDATE event_outbox SET status='delivered',lease_owner='',lease_token='',lease_expires_at=NULL,last_error='',delivered_at=now(),updated_at=now() WHERE id=$1 AND lease_token=$2 AND status='running'`, id, leaseToken)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (r *SQLRepository) FailOutboxEvent(ctx context.Context, id, leaseToken, deliveryErr string, retryAfter time.Duration) error {
	if err := r.check(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if retryAfter < 0 {
		retryAfter = 0
	}
	res, err := r.db.ExecContext(ctx, `UPDATE event_outbox SET status=CASE WHEN attempt_count>=max_attempts THEN 'dead' ELSE 'pending' END,lease_owner='',lease_token='',lease_expires_at=NULL,available_at=now()+($3 * interval '1 second'),last_error=$4,updated_at=now() WHERE id=$1 AND lease_token=$2 AND status='running'`, id, leaseToken, retryAfter.Seconds(), deliveryErr)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (r *SQLRepository) ConsumeDurableNonce(ctx context.Context, namespace, nonceHash, subjectID string, metadata map[string]any, expiresAt time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	nonceHash = strings.ToLower(strings.TrimSpace(nonceHash))
	if namespace == "" || len(nonceHash) != 64 {
		return errors.New("invalid durable nonce")
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now().UTC()) {
		expiresAt = time.Now().UTC().Add(24 * time.Hour)
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Expiry is part of the nonce contract, not merely retention metadata. Remove
	// an expired matching nonce under the same transaction before attempting the
	// single-use insert; a live nonce remains conflict-protected across replicas.
	if _, err := tx.ExecContext(ctx, `DELETE FROM used_nonces WHERE namespace=$1 AND nonce_hash=$2 AND expires_at<=now()`, namespace, nonceHash); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO used_nonces(namespace,nonce_hash,subject_id,metadata,consumed_at,expires_at) VALUES($1,$2,$3,$4::jsonb,now(),$5) ON CONFLICT(namespace,nonce_hash) DO NOTHING`, namespace, nonceHash, strings.TrimSpace(subjectID), string(raw), expiresAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

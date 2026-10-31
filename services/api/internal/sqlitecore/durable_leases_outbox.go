package sqlitecore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func scanScope(s interface{ Scan(...any) error }) (v model.DurableScopeLease, e error) {
	var expires, updated int64
	e = s.Scan(&v.ScopeKey, &v.Owner, &v.LeaseToken, &v.FencingToken, &expires, &updated)
	if e == nil {
		v.ExpiresAt = durableTime(expires)
		v.UpdatedAt = durableTime(updated)
	}
	return
}
func (r *Repository) AcquireDurableScopeLease(ctx context.Context, scope, owner string, ttl time.Duration) (out model.DurableScopeLease, err error) {
	if !durableFieldsNonempty(scope, owner) || !validDurableTTL(ttl) {
		return out, errors.New("invalid scope lease")
	}
	token, e := newLeaseToken()
	if e != nil {
		return out, e
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		var previous int64
		var expires int64
		e := q.QueryRowContext(ctx, `SELECT fencing_token,expires_at FROM durable_scope_leases WHERE scope_key=?`, scope).Scan(&previous, &expires)
		if errors.Is(e, sql.ErrNoRows) {
			_, e = q.ExecContext(ctx, `INSERT INTO durable_scope_leases(scope_key,owner,lease_token,fencing_token,expires_at,updated_at) VALUES(?,?,?,1,?,?)`, scope, owner, token, now+int64(ttl), now)
		} else if e == nil {
			if expires > now {
				return ErrDurableLeaseBusy
			}
			if previous == math.MaxInt64 {
				return errors.New("fencing epoch overflow")
			}
			_, e = q.ExecContext(ctx, `UPDATE durable_scope_leases SET owner=?,lease_token=?,fencing_token=fencing_token+1,expires_at=?,updated_at=? WHERE scope_key=?`, owner, token, now+int64(ttl), now, scope)
		}
		if e != nil {
			return e
		}
		out, e = scanScope(q.QueryRowContext(ctx, `SELECT scope_key,owner,lease_token,fencing_token,expires_at,updated_at FROM durable_scope_leases WHERE scope_key=?`, scope))
		return e
	})
	return
}
func (r *Repository) RenewDurableScopeLease(ctx context.Context, scope, token string, ttl time.Duration) (out model.DurableScopeLease, err error) {
	if !validDurableTTL(ttl) || !durableFieldsNonempty(scope, token) {
		return out, errors.New("invalid renewal")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		res, e := q.ExecContext(ctx, `UPDATE durable_scope_leases SET expires_at=?,updated_at=? WHERE scope_key=? AND lease_token=? AND expires_at>?`, now+int64(ttl), now, scope, token, now)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDurableLeaseLost
		}
		out, e = scanScope(q.QueryRowContext(ctx, `SELECT scope_key,owner,lease_token,fencing_token,expires_at,updated_at FROM durable_scope_leases WHERE scope_key=?`, scope))
		return e
	})
	return
}
func (r *Repository) ReleaseDurableScopeLease(ctx context.Context, scope, token string) error {
	if !durableFieldsNonempty(scope, token) {
		return ErrDurableLeaseLost
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		res, e := q.ExecContext(ctx, `UPDATE durable_scope_leases SET expires_at=0,lease_token='',owner='',updated_at=? WHERE scope_key=? AND lease_token=? AND expires_at>?`, now, scope, token, now)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDurableLeaseLost
		}
		return nil
	})
}

// CommitFencedJob runs a trusted SQLite mutation and produces events in the
// *same transaction* as successful completion. A caller cannot commit any
// mutation after either the job lease or the scope fencing lease expires.
// Side effects outside this SQLite DB MUST NOT occur inside apply; use outbox.
func (r *Repository) CommitFencedJob(ctx context.Context, jobID, jobToken, scope, scopeToken string, fence int64, result []byte, apply func(sqlitedurable.Executor) error, events []model.DurableOutboxEvent) (out model.DurableJob, err error) {
	if len(result) == 0 {
		result = []byte(`{}`)
	}
	if _, err = durableHash(result); err != nil {
		return
	}
	if apply == nil || fence <= 0 {
		return out, errors.New("fenced commit requires nonnil DB mutation and epoch")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		j, e := readJob(ctx, q, jobID)
		if e != nil {
			return e
		}
		if e = validateJobOwnership(j, jobToken, now); e != nil {
			return e
		}
		var t string
		var actual, expiry int64
		e = q.QueryRowContext(ctx, `SELECT lease_token,fencing_token,expires_at FROM durable_scope_leases WHERE scope_key=?`, scope).Scan(&t, &actual, &expiry)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrDurableLeaseLost
		}
		if e != nil {
			return e
		}
		if t == "" || t != scopeToken || actual != fence || expiry <= now {
			return ErrDurableLeaseLost
		}
		if e = apply(q); e != nil {
			return e
		}
		for _, ev := range events {
			if _, _, e = enqueueOutbox(ctx, q, ev, now); e != nil {
				return e
			}
		}
		_, e = q.ExecContext(ctx, `UPDATE durable_jobs SET status='succeeded',result=?,lease_owner='',lease_token='',lease_expires_at=0,updated_at=?,completed_at=? WHERE id=?`, string(result), now, now, jobID)
		if e != nil {
			return e
		}
		if e = finishAttempt(ctx, q, j, now, "succeeded", ""); e != nil {
			return e
		}
		out, e = readJob(ctx, q, jobID)
		return e
	})
	return
}

const outboxColumns = `id,event_type,project_id,aggregate_type,aggregate_id,actor_id,idempotency_key,payload,status,lease_owner,lease_token,lease_fence,lease_expires_at,attempt_count,max_attempts,available_at,last_error,created_at,updated_at,delivered_at`

func scanOutbox(row interface{ Scan(...any) error }) (v model.DurableOutboxEvent, e error) {
	var raw string
	var expires, available, created, updated, delivered int64
	e = row.Scan(&v.ID, &v.EventType, &v.ProjectID, &v.AggregateType, &v.AggregateID, &v.ActorID, &v.IdempotencyKey, &raw, &v.Status, &v.LeaseOwner, &v.LeaseToken, &v.LeaseFence, &expires, &v.AttemptCount, &v.MaxAttempts, &available, &v.LastError, &created, &updated, &delivered)
	if e != nil {
		return v, notFound(e)
	}
	v.Payload = json.RawMessage(raw)
	v.LeaseExpiresAt = durableTime(expires)
	v.AvailableAt = durableTime(available)
	v.CreatedAt = durableTime(created)
	v.UpdatedAt = durableTime(updated)
	v.DeliveredAt = durableTime(delivered)
	return
}
func readOutbox(ctx context.Context, q sqlitedurable.Executor, id string) (model.DurableOutboxEvent, error) {
	return scanOutbox(q.QueryRowContext(ctx, `SELECT `+outboxColumns+` FROM durable_outbox WHERE id=?`, id))
}
func (r *Repository) GetOutboxEvent(ctx context.Context, id string) (out model.DurableOutboxEvent, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error { out, err = readOutbox(ctx, q, id); return err })
	return
}
func enqueueOutbox(ctx context.Context, q sqlitedurable.Executor, v model.DurableOutboxEvent, now int64) (out model.DurableOutboxEvent, created bool, err error) {
	if !durableFieldsNonempty(v.EventType, v.AggregateType, v.AggregateID, v.IdempotencyKey) || (v.ProjectID != "" && !durableFieldsNonempty(v.ProjectID)) || (v.ActorID != "" && !durableFieldsNonempty(v.ActorID)) {
		return out, false, errors.New("invalid outbox identity")
	}
	if v.MaxAttempts == 0 {
		v.MaxAttempts = 8
	}
	if v.MaxAttempts < 1 || v.MaxAttempts > 100 {
		return out, false, errors.New("maxAttempts must be 1..100")
	}
	if len(v.Payload) == 0 {
		v.Payload = []byte(`{}`)
	}
	digest, e := durableHash(v.Payload)
	if e != nil {
		return out, false, e
	}
	existing, e := scanOutbox(q.QueryRowContext(ctx, `SELECT `+outboxColumns+` FROM durable_outbox WHERE event_type=? AND project_id=? AND aggregate_type=? AND aggregate_id=? AND idempotency_key=?`, v.EventType, v.ProjectID, v.AggregateType, v.AggregateID, v.IdempotencyKey))
	if e == nil {
		h, _ := durableHash(existing.Payload)
		if existing.ActorID != v.ActorID || h != digest {
			return out, false, ErrDurableIdempotency
		}
		return existing, false, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return out, false, e
	}
	if v.ID == "" {
		v.ID, e = newID("evt_")
		if e != nil {
			return out, false, e
		}
	}
	if !durableFieldsNonempty(v.ID) {
		return out, false, errors.New("invalid outbox id")
	}
	available := now
	if !v.AvailableAt.IsZero() {
		available = v.AvailableAt.UnixNano()
	}
	_, e = q.ExecContext(ctx, `INSERT INTO durable_outbox(id,event_type,project_id,aggregate_type,aggregate_id,actor_id,idempotency_key,payload,payload_digest,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?,?,?)`, v.ID, v.EventType, v.ProjectID, v.AggregateType, v.AggregateID, v.ActorID, v.IdempotencyKey, string(v.Payload), digest, v.MaxAttempts, available, now, now)
	if e != nil {
		return out, false, conflict(e)
	}
	out, e = readOutbox(ctx, q, v.ID)
	return out, true, e
}
func (r *Repository) EnqueueOutboxEvent(ctx context.Context, v model.DurableOutboxEvent) (out model.DurableOutboxEvent, created bool, err error) {
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var e error
		out, created, e = enqueueOutbox(ctx, q, v, durableNS())
		return e
	})
	return
}

// The transaction is at-least-once delivery, exactly-once external delivery.
func (r *Repository) ClaimOutboxEvents(ctx context.Context, worker string, limit int, ttl time.Duration) (out []model.DurableOutboxEvent, err error) {
	if !durableFieldsNonempty(worker) || limit < 1 || limit > 100 || !validDurableTTL(ttl) {
		return nil, errors.New("invalid outbox claim")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		rows, e := q.QueryContext(ctx, `SELECT id FROM durable_outbox WHERE (status='pending' AND available_at<=?) OR (status='running' AND lease_expires_at<=?) ORDER BY available_at,created_at,id LIMIT ?`, now, now, limit*2+32)
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
			v, e := readOutbox(ctx, q, id)
			if e != nil {
				return e
			}
			if v.AttemptCount >= v.MaxAttempts {
				_, e = q.ExecContext(ctx, `UPDATE durable_outbox SET status='dead',lease_owner='',lease_token='',lease_expires_at=0,last_error='max attempts exhausted',updated_at=? WHERE id=?`, now, id)
				if e != nil {
					return e
				}
				continue
			}
			if v.LeaseFence == math.MaxInt64 {
				return errors.New("outbox fencing overflow")
			}
			token, e := newLeaseToken()
			if e != nil {
				return e
			}
			_, e = q.ExecContext(ctx, `UPDATE durable_outbox SET status='running',lease_owner=?,lease_token=?,lease_fence=lease_fence+1,lease_expires_at=?,attempt_count=attempt_count+1,updated_at=? WHERE id=?`, worker, token, now+int64(ttl), now, id)
			if e != nil {
				return e
			}
			v, e = readOutbox(ctx, q, id)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}
func (r *Repository) RenewOutboxEvent(ctx context.Context, id, token string, ttl time.Duration) (out model.DurableOutboxEvent, err error) {
	if !validDurableTTL(ttl) {
		return out, errors.New("invalid outbox renewal")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		res, e := q.ExecContext(ctx, `UPDATE durable_outbox SET lease_expires_at=?,updated_at=? WHERE id=? AND status='running' AND lease_token=? AND lease_expires_at>?`, now+int64(ttl), now, id, token, now)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDurableLeaseLost
		}
		out, e = readOutbox(ctx, q, id)
		return e
	})
	return
}
func (r *Repository) CompleteOutboxEvent(ctx context.Context, id, token string) error {
	if token == "" {
		return ErrDurableLeaseLost
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		res, e := q.ExecContext(ctx, `UPDATE durable_outbox SET status='delivered',lease_owner='',lease_token='',lease_expires_at=0,delivered_at=?,updated_at=? WHERE id=? AND status='running' AND lease_token=? AND lease_expires_at>?`, now, now, id, token, now)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDurableLeaseLost
		}
		return nil
	})
}
func (r *Repository) FailOutboxEvent(ctx context.Context, id, token, reason string, retryAfter time.Duration) error {
	if token == "" || !validRetryDelay(retryAfter) {
		return ErrDurableLeaseLost
	}
	if len(reason) > 2048 {
		reason = reason[:2048]
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := durableNS()
		v, e := readOutbox(ctx, q, id)
		if e != nil {
			return e
		}
		if v.Status != "running" || v.LeaseToken != token || v.LeaseExpiresAt.UnixNano() <= now {
			return ErrDurableLeaseLost
		}
		status := "pending"
		if v.AttemptCount >= v.MaxAttempts {
			status = "dead"
		}
		res, e := q.ExecContext(ctx, `UPDATE durable_outbox SET status=?,lease_owner='',lease_token='',lease_expires_at=0,available_at=?,last_error=?,updated_at=? WHERE id=? AND status='running' AND lease_token=?`, status, now+int64(retryAfter), reason, now, id, token)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDurableLeaseLost
		}
		return nil
	})
}

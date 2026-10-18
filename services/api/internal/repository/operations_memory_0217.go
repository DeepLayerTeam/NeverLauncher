package repository

import (
	"context"
	"encoding/json"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"time"
)

func (r *MemoryRepository) CompleteOperationJob(_ context.Context, id, token string, result []byte) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	j, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	if j.Status != model.DurableJobStatusRunning || j.LeaseToken != token || !j.LeaseExpiresAt.After(time.Now().UTC()) {
		return model.DurableJob{}, ErrLeaseLost
	}
	if !json.Valid(result) {
		return model.DurableJob{}, ErrConflict
	}
	r.finishMemoryOperationAttempt0217(id, "succeeded", "")
	j.Status = model.DurableJobStatusSucceeded
	j.Result = append([]byte(nil), result...)
	j.LeaseOwner = ""
	j.LeaseToken = ""
	j.LeaseExpiresAt = time.Time{}
	j.UpdatedAt = time.Now().UTC()
	j.CompletedAt = j.UpdatedAt
	r.durableJobs[id] = j
	return j, nil
}
func (r *MemoryRepository) CancelOperationJob(_ context.Context, id, actor string) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	j, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	if j.Status != model.DurableJobStatusPending {
		return model.DurableJob{}, ErrImmutable
	}
	j.Status = model.DurableJobStatusFailed
	j.LastError = "cancelled-by:" + actor
	j.UpdatedAt = time.Now().UTC()
	j.CompletedAt = j.UpdatedAt
	r.durableJobs[id] = j
	return j, nil
}
func (r *MemoryRepository) RetryOperationJob(_ context.Context, id string) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	j, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	if j.Status != model.DurableJobStatusFailed && j.Status != model.DurableJobStatusDead && j.Status != model.DurableJobStatusRevoked {
		return model.DurableJob{}, ErrImmutable
	}
	j.Status = model.DurableJobStatusPending
	if j.MaxAttempts < j.AttemptCount+8 {
		j.MaxAttempts = j.AttemptCount + 8
	}
	j.LastError = ""
	j.AvailableAt = time.Now().UTC()
	j.CompletedAt = time.Time{}
	j.Result = nil
	j.UpdatedAt = j.AvailableAt
	r.durableJobs[id] = j
	return j, nil
}

// Called with durableMu already held: the status transition and journal update
// share the same critical section as the durable job state itself.
func (r *MemoryRepository) finishMemoryOperationAttempt0217(id, status, reason string) {
	rows := r.durableOpAttempts[id]
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Status == "running" {
			rows[i].Status = status
			rows[i].Error = reason
			rows[i].FinishedAt = time.Now().UTC()
			break
		}
	}
	r.durableOpAttempts[id] = rows
}
func (r *MemoryRepository) ListOperationAttempts(_ context.Context, id string) ([]model.DurableJobAttempt, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	if _, ok := r.durableJobs[id]; !ok {
		return nil, ErrNotFound
	}
	rows := r.durableOpAttempts[id]
	out := make([]model.DurableJobAttempt, len(rows))
	copy(out, rows)
	return out, nil
}

func (r *MemoryRepository) FindOperationByKey(_ context.Context, kind, actor, key string) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	id := r.durableJobKeys[kind+"\x00user\x00"+actor+"\x00"+key]
	if id == "" {
		return model.DurableJob{}, ErrNotFound
	}
	job, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	return job, nil
}

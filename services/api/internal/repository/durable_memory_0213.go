package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func (r *MemoryRepository) EnqueueDurableJob(_ context.Context, job model.DurableJob, ttl time.Duration) (model.DurableJob, bool, error) {
	job, err := normalizeDurableJob0213(job)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	key := job.Kind + "\x00" + job.ActorType + "\x00" + job.ActorID + "\x00" + job.IdempotencyKey
	if id := r.durableJobKeys[key]; id != "" {
		existing := r.durableJobs[id]
		if existing.PayloadDigest != job.PayloadDigest {
			return model.DurableJob{}, false, ErrConflict
		}
		return existing, false, nil
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	r.durableJobs[job.ID] = job
	r.durableJobKeys[key] = job.ID
	r.idempotencyDigests[durableJobIdempotencyScope0213(job)+"\x00"+job.IdempotencyKey] = job.PayloadDigest
	return job, true, nil
}

func (r *MemoryRepository) GetDurableJob(_ context.Context, id string) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	j, ok := r.durableJobs[strings.TrimSpace(id)]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	return j, nil
}

func (r *MemoryRepository) leaseJobLocked0213(id, worker string, ttl time.Duration) (model.DurableJob, error) {
	j, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	now := time.Now().UTC()
	if j.Status == model.DurableJobStatusSucceeded || j.Status == model.DurableJobStatusRevoked || j.Status == model.DurableJobStatusFailed || j.Status == model.DurableJobStatusDead {
		return j, ErrImmutable
	}
	if j.Status == model.DurableJobStatusRunning && j.LeaseExpiresAt.After(now) {
		return j, ErrLeaseBusy
	}
	if j.AvailableAt.After(now) || j.AttemptCount >= j.MaxAttempts {
		return j, ErrLeaseBusy
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	token, err := randomHex0213(24)
	if err != nil {
		return model.DurableJob{}, err
	}
	j.Status = model.DurableJobStatusRunning
	j.LeaseOwner = worker
	j.LeaseToken = token
	j.LeaseFence++
	j.LeaseExpiresAt = now.Add(ttl)
	j.AttemptCount++
	j.UpdatedAt = now
	j.LastError = ""
	r.durableJobs[id] = j
	return j, nil
}

func (r *MemoryRepository) LeaseDurableJob(_ context.Context, id, worker string, ttl time.Duration) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	return r.leaseJobLocked0213(strings.TrimSpace(id), strings.TrimSpace(worker), ttl)
}

func (r *MemoryRepository) LeaseDurableJobs(_ context.Context, kind, worker string, limit int, ttl time.Duration) ([]model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	if limit <= 0 {
		limit = 16
	}
	ids := make([]string, 0)
	now := time.Now().UTC()
	for id, j := range r.durableJobs {
		if j.Kind != kind || j.AttemptCount >= j.MaxAttempts || j.AvailableAt.After(now) {
			continue
		}
		if j.Status == model.DurableJobStatusPending || (j.Status == model.DurableJobStatusRunning && !j.LeaseExpiresAt.After(now)) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return r.durableJobs[ids[i]].CreatedAt.Before(r.durableJobs[ids[j]].CreatedAt) })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]model.DurableJob, 0, len(ids))
	for _, id := range ids {
		j, err := r.leaseJobLocked0213(id, worker, ttl)
		if err == nil {
			out = append(out, j)
		}
	}
	return out, nil
}

func (r *MemoryRepository) FailDurableJob(_ context.Context, id, leaseToken, workerErr string, retryAfter time.Duration) (model.DurableJob, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	j, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	if j.Status != model.DurableJobStatusRunning || j.LeaseToken != leaseToken {
		return model.DurableJob{}, ErrLeaseLost
	}
	j.Status = model.DurableJobStatusPending
	if j.AttemptCount >= j.MaxAttempts {
		j.Status = model.DurableJobStatusDead
		j.CompletedAt = time.Now().UTC()
	}
	j.LeaseOwner, j.LeaseToken = "", ""
	j.LeaseExpiresAt = time.Time{}
	j.AvailableAt = time.Now().UTC().Add(retryAfter)
	j.LastError = workerErr
	j.UpdatedAt = time.Now().UTC()
	r.durableJobs[id] = j
	return j, nil
}

func (r *MemoryRepository) TerminateDurableJob(_ context.Context, id, leaseToken, terminalStatus, reason string) (model.DurableJob, error) {
	if terminalStatus != model.DurableJobStatusRevoked && terminalStatus != model.DurableJobStatusFailed && terminalStatus != model.DurableJobStatusDead {
		return model.DurableJob{}, errors.New("недопустимый конечный задача состояние")
	}
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	j, ok := r.durableJobs[id]
	if !ok {
		return model.DurableJob{}, ErrNotFound
	}
	if j.Status != model.DurableJobStatusRunning || j.LeaseToken != leaseToken {
		return model.DurableJob{}, ErrLeaseLost
	}
	j.Status = terminalStatus
	j.LeaseOwner, j.LeaseToken = "", ""
	j.LeaseExpiresAt = time.Time{}
	j.LastError = reason
	j.UpdatedAt = time.Now().UTC()
	j.CompletedAt = j.UpdatedAt
	r.durableJobs[id] = j
	return j, nil
}

func (r *MemoryRepository) AcquireDurableScopeLease(_ context.Context, scopeKey, owner string, ttl time.Duration) (model.DurableScopeLease, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	now := time.Now().UTC()
	if current, ok := r.durableScopeLeases[scopeKey]; ok && current.ExpiresAt.After(now) {
		return model.DurableScopeLease{}, ErrLeaseBusy
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	token, err := randomHex0213(24)
	if err != nil {
		return model.DurableScopeLease{}, err
	}
	fence := int64(1)
	if previous, ok := r.durableScopeLeases[scopeKey]; ok {
		fence = previous.FencingToken + 1
	}
	lease := model.DurableScopeLease{ScopeKey: scopeKey, Owner: owner, LeaseToken: token, FencingToken: fence, ExpiresAt: now.Add(ttl), UpdatedAt: now}
	r.durableScopeLeases[scopeKey] = lease
	return lease, nil
}

func (r *MemoryRepository) RenewDurableScopeLease(_ context.Context, scopeKey, leaseToken string, ttl time.Duration) (model.DurableScopeLease, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	lease, ok := r.durableScopeLeases[strings.TrimSpace(scopeKey)]
	if !ok || lease.LeaseToken != strings.TrimSpace(leaseToken) || !lease.ExpiresAt.After(time.Now().UTC()) {
		return model.DurableScopeLease{}, ErrLeaseLost
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	lease.ExpiresAt = time.Now().UTC().Add(ttl)
	lease.UpdatedAt = time.Now().UTC()
	r.durableScopeLeases[lease.ScopeKey] = lease
	return lease, nil
}

func (r *MemoryRepository) ReleaseDurableScopeLease(_ context.Context, scopeKey, leaseToken string) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	lease, ok := r.durableScopeLeases[scopeKey]
	if !ok || lease.LeaseToken != leaseToken {
		return ErrLeaseLost
	}
	lease.ExpiresAt = time.Now().UTC()
	lease.UpdatedAt = lease.ExpiresAt
	r.durableScopeLeases[scopeKey] = lease
	return nil
}

func (r *MemoryRepository) CommitDurablePublish(_ context.Context, commit model.DurablePublishCommit) (model.ReleaseVersion, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	job, ok := r.durableJobs[commit.JobID]
	if !ok {
		return model.ReleaseVersion{}, ErrNotFound
	}
	now := time.Now().UTC()
	if job.Status != model.DurableJobStatusRunning || job.LeaseToken != commit.JobLeaseToken || job.LeaseExpiresAt.Before(now) {
		return model.ReleaseVersion{}, ErrLeaseLost
	}
	lease, ok := r.durableScopeLeases[commit.ScopeKey]
	if !ok || lease.LeaseToken != commit.ScopeLeaseToken || lease.FencingToken != commit.ScopeFencingToken || lease.ExpiresAt.Before(now) {
		return model.ReleaseVersion{}, ErrLeaseLost
	}
	idx := -1
	for i := range r.releases {
		if r.releases[i].ID == job.ResourceID && r.releases[i].ProjectID == job.ProjectID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return model.ReleaseVersion{}, ErrNotFound
	}
	rel := r.releases[idx]
	if rel.Status == "published" {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if strings.TrimSpace(commit.ExpectedStatus) == "" || rel.Status != commit.ExpectedStatus {
		return model.ReleaseVersion{}, ErrConflict
	}
	raw, _ := json.Marshal(rel.Manifest)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != commit.ExpectedManifestDigest {
		return model.ReleaseVersion{}, ErrConflict
	}
	r.validationMu.Lock()
	var latest model.IntegrityCheckResult
	for _, x := range r.integrityChecks {
		if x.PackageID == rel.ID && (latest.CheckedAt.IsZero() || x.CheckedAt.After(latest.CheckedAt)) {
			latest = x
		}
	}
	r.validationMu.Unlock()
	if latest.Result != "passed" || latest.ManifestDigest != commit.ExpectedManifestDigest || latest.ArtifactDigest != commit.ExpectedArtifactDigest {
		return model.ReleaseVersion{}, ErrConflict
	}
	rel.Status = "published"
	rel.PublishedAt = now
	r.releases[idx] = rel
	result, _ := json.Marshal(map[string]any{"releaseId": rel.ID, "status": "published", "publishedAt": now})
	job.Status = model.DurableJobStatusSucceeded
	job.Result = result
	job.CompletedAt, job.UpdatedAt = now, now
	job.LeaseOwner, job.LeaseToken = "", ""
	job.LeaseExpiresAt = time.Time{}
	r.durableJobs[job.ID] = job
	payload, _ := json.Marshal(map[string]any{"packageId": rel.ID, "projectId": rel.ProjectID, "profileId": rel.ProfileID, "channel": rel.Channel, "version": rel.Version, "status": "published", "actorId": commit.ActorID})
	for _, typ := range []string{"package.published", "release.published"} {
		idSum := sha256.Sum256([]byte(job.ID + "\x00" + typ))
		id := "out_" + hex.EncodeToString(idSum[:10])
		key := "publish:" + rel.ID + ":" + commit.ExpectedManifestDigest + ":" + typ
		if _, exists := r.durableOutbox[key]; !exists {
			r.durableOutbox[key] = model.DurableOutboxEvent{ID: id, EventType: typ, ProjectID: rel.ProjectID, AggregateType: "release", AggregateID: rel.ID, ActorID: commit.ActorID, IdempotencyKey: key, Payload: payload, Status: model.OutboxStatusPending, MaxAttempts: 12, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		}
	}
	return rel, nil
}

func (r *MemoryRepository) ClaimOutboxEvents(_ context.Context, worker string, limit int, ttl time.Duration) ([]model.DurableOutboxEvent, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	if limit <= 0 {
		limit = 32
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	now := time.Now().UTC()
	keys := make([]string, 0)
	for key, e := range r.durableOutbox {
		if e.AttemptCount >= e.MaxAttempts || e.AvailableAt.After(now) {
			continue
		}
		if e.Status == model.OutboxStatusPending || (e.Status == model.OutboxStatusRunning && !e.LeaseExpiresAt.After(now)) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]model.DurableOutboxEvent, 0, len(keys))
	for _, key := range keys {
		e := r.durableOutbox[key]
		token, _ := randomHex0213(24)
		e.Status = model.OutboxStatusRunning
		e.LeaseOwner, e.LeaseToken = worker, token
		e.LeaseFence++
		e.LeaseExpiresAt = now.Add(ttl)
		e.AttemptCount++
		e.UpdatedAt = now
		r.durableOutbox[key] = e
		out = append(out, e)
	}
	return out, nil
}

func (r *MemoryRepository) CompleteOutboxEvent(_ context.Context, id, leaseToken string) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	for key, e := range r.durableOutbox {
		if e.ID == id && e.LeaseToken == leaseToken && e.Status == model.OutboxStatusRunning {
			e.Status = model.OutboxStatusDelivered
			e.LeaseOwner, e.LeaseToken = "", ""
			e.LeaseExpiresAt = time.Time{}
			e.DeliveredAt, e.UpdatedAt = time.Now().UTC(), time.Now().UTC()
			r.durableOutbox[key] = e
			return nil
		}
	}
	return ErrLeaseLost
}

func (r *MemoryRepository) FailOutboxEvent(_ context.Context, id, leaseToken, deliveryErr string, retryAfter time.Duration) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	for key, e := range r.durableOutbox {
		if e.ID == id && e.LeaseToken == leaseToken && e.Status == model.OutboxStatusRunning {
			e.Status = model.OutboxStatusPending
			if e.AttemptCount >= e.MaxAttempts {
				e.Status = model.OutboxStatusDead
			}
			e.LeaseOwner, e.LeaseToken = "", ""
			e.LeaseExpiresAt = time.Time{}
			e.AvailableAt = time.Now().UTC().Add(retryAfter)
			e.LastError, e.UpdatedAt = deliveryErr, time.Now().UTC()
			r.durableOutbox[key] = e
			return nil
		}
	}
	return ErrLeaseLost
}

func (r *MemoryRepository) ConsumeDurableNonce(_ context.Context, namespace, nonceHash, subjectID string, metadata map[string]any, expiresAt time.Time) error {
	_ = subjectID
	_ = metadata
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	key := strings.TrimSpace(namespace) + "\x00" + strings.ToLower(strings.TrimSpace(nonceHash))
	if old, ok := r.durableNonces[key]; ok && old.After(time.Now().UTC()) {
		return ErrConflict
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now().UTC()) {
		expiresAt = time.Now().UTC().Add(24 * time.Hour)
	}
	r.durableNonces[key] = expiresAt
	return nil
}

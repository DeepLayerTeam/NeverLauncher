// SQLite-backed HTTP repository delegations. Every mutation is serialized and
// synchronously checkpointed to the durable store before returning success.
// Generated from exported MemoryRepository methods; no method is silently lost.
package repository

import (
	"context"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"time"
)

func (r *SQLiteHTTPRepository0372) QueryAudit(arg0 context.Context, q AuditQuery) (out0 AuditQueryResult, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.QueryAudit(arg0, q)
	return
}

func (r *SQLiteHTTPRepository0372) ListManagedProviders02910(arg0 context.Context) (out0 []ManagedProviderHead02910, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListManagedProviders02910(arg0)
	return
}

func (r *SQLiteHTTPRepository0372) SaveManagedProviderDraft02910(arg0 context.Context, v ManagedProviderRevision02910) (out0 ManagedProviderRevision02910, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveManagedProviderDraft02910(arg0, v)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ActivateManagedProvider02910(arg0 context.Context, id string, target int64, expected int64, actor string, reason string) (out0 ManagedProviderHead02910, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ActivateManagedProvider02910(arg0, id, target, expected, actor, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListActiveManagedProviders02910(arg0 context.Context) (out0 []ManagedProviderRevision02910, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListActiveManagedProviders02910(arg0)
	return
}

func (r *SQLiteHTTPRepository0372) ListRecentMinecraftClients0289(ctx context.Context, now time.Time, age time.Duration) (out0 []BackendMinecraftClient0289, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListRecentMinecraftClients0289(ctx, now, age)
	return
}

func (r *SQLiteHTTPRepository0372) CreateBuildWorkspace(arg0 context.Context, w BuildWorkspace) (out0 BuildWorkspace, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CreateBuildWorkspace(arg0, w)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetBuildWorkspace(arg0 context.Context, id string) (out0 BuildWorkspace, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetBuildWorkspace(arg0, id)
	return
}

func (r *SQLiteHTTPRepository0372) ListBuildWorkspaces(arg0 context.Context, projectID string, ownerID string) (out0 []BuildWorkspace, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListBuildWorkspaces(arg0, projectID, ownerID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveBuildWorkspace(arg0 context.Context, w BuildWorkspace) (out0 BuildWorkspace, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveBuildWorkspace(arg0, w)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetChannelHead(arg0 context.Context, projectID string, profileID string, channel string) (out0 model.ChannelHead, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetChannelHead(arg0, projectID, profileID, channel)
	return
}

func (r *SQLiteHTTPRepository0372) UpdateDraftComponentCatalog0248(projectID string, versionID string, expected uint64, cat model.ComponentCatalog0241) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.UpdateDraftComponentCatalog0248(projectID, versionID, expected, cat)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveTrustedDevice(ctx context.Context, device model.TrustedDevice) (out0 model.TrustedDevice, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveTrustedDevice(ctx, device)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetTrustedDevice(userID string, deviceID string) (out0 model.TrustedDevice, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetTrustedDevice(userID, deviceID)
	return
}

func (r *SQLiteHTTPRepository0372) GetTrustedDeviceByID(deviceID string) (out0 model.TrustedDevice, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetTrustedDeviceByID(deviceID)
	return
}

func (r *SQLiteHTTPRepository0372) ListTrustedDevices(userID string, status string) (out0 []model.TrustedDevice) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListTrustedDevices(userID, status)
	return
}

func (r *SQLiteHTTPRepository0372) RenameTrustedDevice(userID string, deviceID string, name string) (out0 model.TrustedDevice, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RenameTrustedDevice(userID, deviceID, name)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeTrustedDevice(ctx context.Context, userID string, deviceID string, reason string) (out0 model.DeviceRevocationResult, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RevokeTrustedDevice(ctx, userID, deviceID, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeOtherTrustedDevices(ctx context.Context, userID string, exceptDeviceID string, reason string) (out0 model.DeviceRevocationBatch, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RevokeOtherTrustedDevices(ctx, userID, exceptDeviceID, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) TouchTrustedDevice(ctx context.Context, userID string, deviceID string, ip string, userAgent string) (out0 model.TrustedDevice, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.TouchTrustedDevice(ctx, userID, deviceID, ip, userAgent)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) AttestTrustedDevice(ctx context.Context, userID string, deviceID string, method string, attestedAt time.Time, expiresAt time.Time) (out0 model.TrustedDevice, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.AttestTrustedDevice(ctx, userID, deviceID, method, attestedAt, expiresAt)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveDeviceChallenge(ctx context.Context, challenge model.DeviceChallenge) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveDeviceChallenge(ctx, challenge)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ConsumeDeviceChallenge(ctx context.Context, id string, userID string, deviceID string, purpose string, challengeHash string, now time.Time) (out0 model.DeviceChallenge, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ConsumeDeviceChallenge(ctx, id, userID, deviceID, purpose, challengeHash, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) EnqueueDurableJob(arg0 context.Context, job model.DurableJob, ttl time.Duration) (out0 model.DurableJob, out1 bool, out2 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1, out2 = r.mem.EnqueueDurableJob(arg0, job, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out2 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetDurableJob(arg0 context.Context, id string) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetDurableJob(arg0, id)
	return
}

func (r *SQLiteHTTPRepository0372) LeaseDurableJob(arg0 context.Context, id string, worker string, ttl time.Duration) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.LeaseDurableJob(arg0, id, worker, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) LeaseDurableJobs(arg0 context.Context, kind string, worker string, limit int, ttl time.Duration) (out0 []model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.LeaseDurableJobs(arg0, kind, worker, limit, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) FailDurableJob(arg0 context.Context, id string, leaseToken string, workerErr string, retryAfter time.Duration) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.FailDurableJob(arg0, id, leaseToken, workerErr, retryAfter)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) TerminateDurableJob(arg0 context.Context, id string, leaseToken string, terminalStatus string, reason string) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.TerminateDurableJob(arg0, id, leaseToken, terminalStatus, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) AcquireDurableScopeLease(arg0 context.Context, scopeKey string, owner string, ttl time.Duration) (out0 model.DurableScopeLease, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.AcquireDurableScopeLease(arg0, scopeKey, owner, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RenewDurableScopeLease(arg0 context.Context, scopeKey string, leaseToken string, ttl time.Duration) (out0 model.DurableScopeLease, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RenewDurableScopeLease(arg0, scopeKey, leaseToken, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ReleaseDurableScopeLease(arg0 context.Context, scopeKey string, leaseToken string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ReleaseDurableScopeLease(arg0, scopeKey, leaseToken)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

// CommitDurablePublish is implemented in sqlite_http_stable_0374.go. The
// release, channel head, durable job, outbox and one-use grant share one WAL commit.
func (r *SQLiteHTTPRepository0372) ClaimOutboxEvents(arg0 context.Context, worker string, limit int, ttl time.Duration) (out0 []model.DurableOutboxEvent, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ClaimOutboxEvents(arg0, worker, limit, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) CompleteOutboxEvent(arg0 context.Context, id string, leaseToken string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.CompleteOutboxEvent(arg0, id, leaseToken)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) FailOutboxEvent(arg0 context.Context, id string, leaseToken string, deliveryErr string, retryAfter time.Duration) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.FailOutboxEvent(arg0, id, leaseToken, deliveryErr, retryAfter)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ConsumeDurableNonce(arg0 context.Context, namespace string, nonceHash string, subjectID string, metadata map[string]any, expiresAt time.Time) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ConsumeDurableNonce(arg0, namespace, nonceHash, subjectID, metadata, expiresAt)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) PublishExtensionEvent(ctx context.Context, in model.ExtensionEvent) (out0 model.ExtensionEvent, out1 bool, out2 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1, out2 = r.mem.PublishExtensionEvent(ctx, in)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out2 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionEventSubscription(ctx context.Context, in model.ExtensionEventSubscription) (out0 model.ExtensionEventSubscription, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionEventSubscription(ctx, in)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeleteExtensionEventSubscription(ctx context.Context, id int64, extensionID string, scope string, scopeID string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteExtensionEventSubscription(ctx, id, extensionID, scope, scopeID)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SetExtensionEventSubscriptionsEnabled(ctx context.Context, extensionID string, scope string, scopeID string, enabled bool) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SetExtensionEventSubscriptionsEnabled(ctx, extensionID, scope, scopeID, enabled)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionEventSubscriptions(ctx context.Context, extensionID string, scope string, scopeID string) (out0 []model.ExtensionEventSubscription, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionEventSubscriptions(ctx, extensionID, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionEventSubscriptionsForType(ctx context.Context, eventType string, mode string) (out0 []model.ExtensionEventSubscription, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionEventSubscriptionsForType(ctx, eventType, mode)
	return
}

func (r *SQLiteHTTPRepository0372) LeaseExtensionEventDeliveries(ctx context.Context, limit int, leaseUntil time.Time) (out0 []model.ExtensionEventDeliveryEnvelope, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.LeaseExtensionEventDeliveries(ctx, limit, leaseUntil)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) CompleteExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, when time.Time) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.CompleteExtensionEventDelivery(ctx, id, leaseToken, when)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RetryExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, next time.Time, msg string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.RetryExtensionEventDelivery(ctx, id, leaseToken, next, msg)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeadLetterExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, msg string, when time.Time) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeadLetterExtensionEventDelivery(ctx, id, leaseToken, msg, when)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionEventDeadLetters(ctx context.Context, extensionID string, limit int) (out0 []model.ExtensionEventDeadLetter, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionEventDeadLetters(ctx, extensionID, limit)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionInstallState(ctx context.Context, extensionID string, scope string, scopeID string) (out0 model.ExtensionInstall, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionInstallState(ctx, extensionID, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionInstallStates(ctx context.Context, scope string, scopeID string) (out0 []model.ExtensionInstall, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionInstallStates(ctx, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) TransitionExtensionInstall(ctx context.Context, transition model.ExtensionLifecycleTransition) (out0 model.ExtensionInstall, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.TransitionExtensionInstall(ctx, transition)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionInstallRevisions(ctx context.Context, extensionID string, scope string, scopeID string, limit int) (out0 []model.ExtensionInstallRevision, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionInstallRevisions(ctx, extensionID, scope, scopeID, limit)
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionRegistryPublisher(ctx context.Context, publisher model.ExtensionRegistryPublisher) (out0 model.ExtensionRegistryPublisher, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionRegistryPublisher(ctx, publisher)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionRegistryPublishers(ctx context.Context) (out0 []model.ExtensionRegistryPublisher, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionRegistryPublishers(ctx)
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionRegistryPublisherKey(ctx context.Context, key model.ExtensionRegistryPublisherKey) (out0 model.ExtensionRegistryPublisherKey, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionRegistryPublisherKey(ctx, key)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionRegistryPublisherKey(ctx context.Context, publisherID string, fingerprint string) (out0 model.ExtensionRegistryPublisherKey, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionRegistryPublisherKey(ctx, publisherID, fingerprint)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionRegistryPublisherKeys(ctx context.Context, publisherID string) (out0 []model.ExtensionRegistryPublisherKey, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionRegistryPublisherKeys(ctx, publisherID)
	return
}

func (r *SQLiteHTTPRepository0372) PublishExtensionRegistryVersion(ctx context.Context, publication model.ExtensionRegistryPublication) (out0 model.ExtensionRegistryVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.PublishExtensionRegistryVersion(ctx, publication)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SearchExtensionRegistry(ctx context.Context, query model.ExtensionRegistrySearch) (out0 []model.ExtensionRegistryVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SearchExtensionRegistry(ctx, query)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionRegistryVersion(ctx context.Context, extensionID string, version string) (out0 model.ExtensionRegistryVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionRegistryVersion(ctx, extensionID, version)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionRegistryExtension(ctx context.Context, extensionID string) (out0 model.ExtensionRegistryExtension, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionRegistryExtension(ctx, extensionID)
	return
}

func (r *SQLiteHTTPRepository0372) SetExtensionRegistryChannel(ctx context.Context, extensionID string, channel string, version string) (out0 model.ExtensionRegistryVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SetExtensionRegistryChannel(ctx, extensionID, channel, version)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) YankExtensionRegistryVersion(ctx context.Context, extensionID string, version string, reason string) (out0 model.ExtensionRegistryVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.YankExtensionRegistryVersion(ctx, extensionID, version, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionPermissionGrants(ctx context.Context, extensionID string, scope string, scopeID string) (out0 []model.ExtensionPermissionGrant, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionPermissionGrants(ctx, extensionID, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) GrantExtensionPermission(ctx context.Context, grant model.ExtensionPermissionGrant) (out0 model.ExtensionPermissionGrant, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GrantExtensionPermission(ctx, grant)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeExtensionPermission(ctx context.Context, extensionID string, scope string, scopeID string, permission string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.RevokeExtensionPermission(ctx, extensionID, scope, scopeID, permission)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) PutExtensionSecret(ctx context.Context, secret model.ExtensionSecret) (out0 model.ExtensionSecret, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.PutExtensionSecret(ctx, secret)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionSecret(ctx context.Context, extensionID string, scope string, scopeID string, name string) (out0 model.ExtensionSecret, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionSecret(ctx, extensionID, scope, scopeID, name)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionSecrets(ctx context.Context, extensionID string, scope string, scopeID string) (out0 []model.ExtensionSecretMetadata, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionSecrets(ctx, extensionID, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) DeleteExtensionSecret(ctx context.Context, extensionID string, scope string, scopeID string, name string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteExtensionSecret(ctx, extensionID, scope, scopeID, name)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionTrustPolicy(ctx context.Context) (out0 model.ExtensionTrustPolicy, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionTrustPolicy(ctx)
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionTrustPolicy(ctx context.Context, p model.ExtensionTrustPolicy) (out0 model.ExtensionTrustPolicy, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionTrustPolicy(ctx, p)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeExtensionRegistryPublisherKey(ctx context.Context, publisherID string, fingerprint string) (out0 model.ExtensionRegistryPublisherKey, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RevokeExtensionRegistryPublisherKey(ctx, publisherID, fingerprint)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionQuarantine(ctx context.Context, e model.ExtensionQuarantineEntry) (out0 model.ExtensionQuarantineEntry, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionQuarantine(ctx, e)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionQuarantine(ctx context.Context, activeOnly bool) (out0 []model.ExtensionQuarantineEntry, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionQuarantine(ctx, activeOnly)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionQuarantine(ctx context.Context, id string) (out0 model.ExtensionQuarantineEntry, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionQuarantine(ctx, id)
	return
}

func (r *SQLiteHTTPRepository0372) ReleaseExtensionQuarantine(ctx context.Context, id string, actor string) (out0 model.ExtensionQuarantineEntry, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ReleaseExtensionQuarantine(ctx, id, actor)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) IsExtensionPackageQuarantined(ctx context.Context, identity string) (out0 bool, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.IsExtensionPackageQuarantined(ctx, identity)
	return
}

func (r *SQLiteHTTPRepository0372) SetExtensionEmergencyDisable(ctx context.Context, e model.ExtensionEmergencyDisable) (out0 model.ExtensionEmergencyDisable, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SetExtensionEmergencyDisable(ctx, e)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionEmergencyDisable(ctx context.Context, id string, scope string, scopeID string) (out0 model.ExtensionEmergencyDisable, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionEmergencyDisable(ctx, id, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionEmergencyDisables(ctx context.Context, activeOnly bool) (out0 []model.ExtensionEmergencyDisable, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionEmergencyDisables(ctx, activeOnly)
	return
}

func (r *SQLiteHTTPRepository0372) ClearExtensionEmergencyDisable(ctx context.Context, id string, scope string, scopeID string, actor string) (out0 model.ExtensionEmergencyDisable, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ClearExtensionEmergencyDisable(ctx, id, scope, scopeID, actor)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionUpdatePins(ctx context.Context, scope string, scopeID string) (out0 []model.ExtensionUpdatePin, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionUpdatePins(ctx, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) SetExtensionUpdatePin(ctx context.Context, p model.ExtensionUpdatePin) (out0 model.ExtensionUpdatePin, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SetExtensionUpdatePin(ctx, p)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeleteExtensionUpdatePin(ctx context.Context, id string, scope string, scopeID string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteExtensionUpdatePin(ctx, id, scope, scopeID)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) AcquireExtensionUpdateLease(ctx context.Context, scope string, scopeID string, owner string, ttl time.Duration) (out0 bool, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.AcquireExtensionUpdateLease(ctx, scope, scopeID, owner, ttl)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ReleaseExtensionUpdateLease(ctx context.Context, scope string, scopeID string, owner string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ReleaseExtensionUpdateLease(ctx, scope, scopeID, owner)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionUpdateTransaction(ctx context.Context, tx model.ExtensionUpdateTransaction) (out0 model.ExtensionUpdateTransaction, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionUpdateTransaction(ctx, tx)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionUpdateTransaction(ctx context.Context, id string) (out0 model.ExtensionUpdateTransaction, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionUpdateTransaction(ctx, id)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionUpdateTransactions(ctx context.Context, scope string, scopeID string, status string) (out0 []model.ExtensionUpdateTransaction, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionUpdateTransactions(ctx, scope, scopeID, status)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensions(ctx context.Context) (out0 []model.Extension, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensions(ctx)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtension(ctx context.Context, id string) (out0 model.Extension, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtension(ctx, id)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionVersions(ctx context.Context, extensionID string) (out0 []model.ExtensionVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionVersions(ctx, extensionID)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionVersion(ctx context.Context, extensionID string, version string) (out0 model.ExtensionVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionVersion(ctx, extensionID, version)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionPermissions(ctx context.Context, extensionID string, version string) (out0 []string, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionPermissions(ctx, extensionID, version)
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionDependencies(ctx context.Context, extensionID string, version string) (out0 []model.ExtensionDependency, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionDependencies(ctx, extensionID, version)
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionVersion(ctx context.Context, manifest model.ExtensionManifest) (out0 model.ExtensionVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionVersion(ctx, manifest)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListExtensionInstalls(ctx context.Context, scope string, scopeID string) (out0 []model.ExtensionInstall, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListExtensionInstalls(ctx, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) GetExtensionInstall(ctx context.Context, extensionID string, scope string, scopeID string) (out0 model.ExtensionInstall, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetExtensionInstall(ctx, extensionID, scope, scopeID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveExtensionInstall(ctx context.Context, install model.ExtensionInstall) (out0 model.ExtensionInstall, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveExtensionInstall(ctx, install)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeleteExtensionInstall(ctx context.Context, extensionID string, scope string, scopeID string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteExtensionInstall(ctx, extensionID, scope, scopeID)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) CreateGravitProfileWorkspace02210(ctx context.Context, p model.Profile, w BuildWorkspace) (out0 model.Profile, out1 BuildWorkspace, out2 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1, out2 = r.mem.CreateGravitProfileWorkspace02210(ctx, p, w)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out2 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveHardwareEvidence(arg0 context.Context, e model.DeviceHardwareEvidence) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveHardwareEvidence(arg0, e)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) LatestHardwareEvidence(arg0 context.Context, userID string, deviceID string) (out0 model.DeviceHardwareEvidence, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.LatestHardwareEvidence(arg0, userID, deviceID)
	return
}

func (r *SQLiteHTTPRepository0372) ObserveHWID0299(arg0 context.Context, userID string, deviceID string, digest string, now time.Time) (out0 HWIDObservation0299, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ObserveHWID0299(arg0, userID, deviceID, digest, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetHWID0299(arg0 context.Context, userID string, deviceID string, now time.Time) (out0 HWIDObservation0299, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetHWID0299(arg0, userID, deviceID, now)
	return
}

func (r *SQLiteHTTPRepository0372) ConfirmHWID0299(arg0 context.Context, userID string, deviceID string, now time.Time) (out0 HWIDObservation0299, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ConfirmHWID0299(arg0, userID, deviceID, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ForgetHWID0299(arg0 context.Context, userID string, deviceID string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ForgetHWID0299(arg0, userID, deviceID)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SubmitHWIDAppeal0299(arg0 context.Context, a HWIDAppeal0299) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SubmitHWIDAppeal0299(arg0, a)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListHWIDAppeals0299(arg0 context.Context, userID string) (out0 []HWIDAppeal0299, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListHWIDAppeals0299(arg0, userID)
	return
}

func (r *SQLiteHTTPRepository0372) ResolveHWIDAppeal0299(arg0 context.Context, id string, actor string, decision string, now time.Time) (out0 HWIDAppeal0299, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ResolveHWIDAppeal0299(arg0, id, actor, decision, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) PruneHWID0299(arg0 context.Context, now time.Time) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.PruneHWID0299(arg0, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ReplacePasswordIfMatch0295(arg0 context.Context, userID string, priorHash string, newHash string) (out0 bool, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ReplacePasswordIfMatch0295(arg0, userID, priorHash, newHash)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveMeasuredBoot0315(arg0 context.Context, e model.MeasuredBootEvidence0315) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveMeasuredBoot0315(arg0, e)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) LatestMeasuredBoot0315(arg0 context.Context, userID string, deviceID string) (out0 model.MeasuredBootEvidence0315, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.LatestMeasuredBoot0315(arg0, userID, deviceID)
	return
}

func (r *SQLiteHTTPRepository0372) ListProjects() (out0 []model.Project) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListProjects()
	return
}

func (r *SQLiteHTTPRepository0372) GetProject(id string) (out0 model.Project, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetProject(id)
	return
}

func (r *SQLiteHTTPRepository0372) SaveProject(project model.Project) (out0 model.Project, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveProject(project)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListProfiles(projectID string) (out0 []model.Profile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListProfiles(projectID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveProfile(profile model.Profile) (out0 model.Profile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveProfile(profile)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListProfileRevisions(projectID string, profileID string) (out0 []model.ProfileSnapshot, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListProfileRevisions(projectID, profileID)
	return
}

func (r *SQLiteHTTPRepository0372) ListChannels(projectID string) (out0 []model.ReleaseChannel, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListChannels(projectID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveChannel(channel model.ReleaseChannel) (out0 model.ReleaseChannel, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveChannel(channel)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListVersions(projectID string) (out0 []model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListVersions(projectID)
	return
}

func (r *SQLiteHTTPRepository0372) ListFiles(projectID string, versionID string) (out0 []model.FileObject, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListFiles(projectID, versionID)
	return
}

func (r *SQLiteHTTPRepository0372) ListUsers() (out0 []model.User) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListUsers()
	return
}

func (r *SQLiteHTTPRepository0372) GetUser(id string) (out0 model.User, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetUser(id)
	return
}

func (r *SQLiteHTTPRepository0372) GetUserByEmail(email string) (out0 model.User, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetUserByEmail(email)
	return
}

func (r *SQLiteHTTPRepository0372) SaveUser(user model.User) (out0 model.User, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	if len(r.mem.users) == 0 && (user.RoleID != "owner" || user.Status == "disabled") {
		return model.User{}, ErrConflict
	}
	if existing, err := r.mem.GetUser(user.ID); err == nil && existing.RoleID == "owner" && user.RoleID != "owner" {
		if !sqliteHTTPOtherActiveOwner0372(r.mem.users, user.ID) {
			return model.User{}, ErrConflict
		}
	}
	out0, out1 = r.mem.SaveUser(user)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SetUserDisabled(id string, disabled bool) (out0 model.User, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	if disabled {
		if user, err := r.mem.GetUser(id); err == nil && user.RoleID == "owner" && !sqliteHTTPOtherActiveOwner0372(r.mem.users, id) {
			return model.User{}, ErrConflict
		}
	}
	out0, out1 = r.mem.SetUserDisabled(id, disabled)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SetUserPassword(id string, passwordHash string) (out0 model.User, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SetUserPassword(id, passwordHash)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) TouchUserLogin(id string) (out0 model.User, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.TouchUserLogin(id)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetAuthIdentity(provider string, subject string) (out0 model.AuthIdentity, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetAuthIdentity(provider, subject)
	return
}

func (r *SQLiteHTTPRepository0372) GetAuthIdentityByIssuer(provider string, issuer string, subject string) (out0 model.AuthIdentity, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetAuthIdentityByIssuer(provider, issuer, subject)
	return
}

func (r *SQLiteHTTPRepository0372) ListAuthIdentities(userID string) (out0 []model.AuthIdentity) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListAuthIdentities(userID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveAuthIdentity(identity model.AuthIdentity) (out0 model.AuthIdentity, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveAuthIdentity(identity)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveFederatedUser(arg0 context.Context, user model.User, identity model.AuthIdentity) (out0 model.User, out1 model.AuthIdentity, out2 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	if len(r.mem.users) == 0 {
		return model.User{}, model.AuthIdentity{}, ErrConflict
	}
	out0, out1, out2 = r.mem.SaveFederatedUser(arg0, user, identity)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out2 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) TouchAuthIdentity(id string) (out0 model.AuthIdentity, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.TouchAuthIdentity(id)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListRoles() (out0 []model.Role) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListRoles()
	return
}

func (r *SQLiteHTTPRepository0372) ListAuditEvents() (out0 []model.AuditEvent) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListAuditEvents()
	return
}

func (r *SQLiteHTTPRepository0372) AddAuditEvent(event model.AuditEvent) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	r.mem.AddAuditEvent(event)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		panic(e)
	}
}

func (r *SQLiteHTTPRepository0372) SetAuditEventSink(sink func(model.AuditEvent)) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	r.auditSink = sink
}

func (r *SQLiteHTTPRepository0372) GetManifest(projectID string, profileID string, channel string) (out0 model.Manifest, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetManifest(projectID, profileID, channel)
	return
}

func (r *SQLiteHTTPRepository0372) PublishVersion(projectID string, profileID string, channel string, version string) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.PublishVersion(projectID, profileID, channel, version)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) PublishVersionWithManifest(projectID string, profileID string, channel string, version string, manifest model.Manifest) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.PublishVersionWithManifest(projectID, profileID, channel, version, manifest)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) PublishVersionWithManifestCAS(projectID string, profileID string, channel string, version string, manifest model.Manifest, expected int64) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.PublishVersionWithManifestCAS(projectID, profileID, channel, version, manifest, expected)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) CreateVersion(projectID string, profileID string, channel string, version string) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CreateVersion(projectID, profileID, channel, version)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) CreateVersionV3(projectID string, profileID string, channel string, version string) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CreateVersionV3(projectID, profileID, channel, version)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) UpdateVersionStatus(projectID string, versionID string, status string) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.UpdateVersionStatus(projectID, versionID, status)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) UpdateVersionManifest(projectID string, versionID string, manifest model.Manifest) (out0 model.ReleaseVersion, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.UpdateVersionManifest(projectID, versionID, manifest)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) AddFile(file model.FileObject) (out0 model.FileObject, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.AddFile(file)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ExportProject(projectID string) (out0 map[string]any, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ExportProject(projectID)
	return
}

func (r *SQLiteHTTPRepository0372) ImportProject(payload map[string]any) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ImportProject(payload)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) AddTelemetryEvent(event model.TelemetryEvent) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	r.mem.AddTelemetryEvent(event)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		panic(e)
	}
}

func (r *SQLiteHTTPRepository0372) AddCrashReport(report model.CrashReport) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	r.mem.AddCrashReport(report)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		panic(e)
	}
}

func (r *SQLiteHTTPRepository0372) ListTelemetryEvents() (out0 []model.TelemetryEvent) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListTelemetryEvents()
	return
}

func (r *SQLiteHTTPRepository0372) ListCrashReports() (out0 []model.CrashReport) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.ListCrashReports()
	return
}

func (r *SQLiteHTTPRepository0372) GetProviderCredential(userID string, provider string) (out0 model.ProviderCredential, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetProviderCredential(userID, provider)
	return
}

func (r *SQLiteHTTPRepository0372) GetProviderCredentialByIdentity(userID string, identityID string) (out0 model.ProviderCredential, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetProviderCredentialByIdentity(userID, identityID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveProviderCredential(item model.ProviderCredential) (out0 model.ProviderCredential, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveProviderCredential(item)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeleteProviderCredential(userID string, provider string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteProviderCredential(userID, provider)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeleteProviderCredentialByIdentity(userID string, identityID string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteProviderCredentialByIdentity(userID, identityID)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetMinecraftProfileByUser(userID string) (out0 model.MinecraftProfile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetMinecraftProfileByUser(userID)
	return
}

func (r *SQLiteHTTPRepository0372) GetMinecraftProfileByUUID(uuid string) (out0 model.MinecraftProfile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetMinecraftProfileByUUID(uuid)
	return
}

func (r *SQLiteHTTPRepository0372) GetMinecraftProfileByName(name string) (out0 model.MinecraftProfile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetMinecraftProfileByName(name)
	return
}

func (r *SQLiteHTTPRepository0372) SaveMinecraftProfile(item model.MinecraftProfile) (out0 model.MinecraftProfile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveMinecraftProfile(item)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveMinecraftSession(item model.MinecraftSession) (out0 model.MinecraftSession, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveMinecraftSession(item)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetMinecraftSessionByTokenHash(hash string) (out0 model.MinecraftSession, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetMinecraftSessionByTokenHash(hash)
	return
}

func (r *SQLiteHTTPRepository0372) TouchMinecraftSession(id string) (out0 model.MinecraftSession, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.TouchMinecraftSession(id)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeMinecraftSession(id string, reason string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.RevokeMinecraftSession(id, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeMinecraftSessionsByNeverSession(neverSessionID string, reason string) (out0 int) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.RevokeMinecraftSessionsByNeverSession(neverSessionID, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		panic(e)
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeMinecraftSessionsByUser(userID string, reason string) (out0 int) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.RevokeMinecraftSessionsByUser(userID, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		panic(e)
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetMinecraftSession(id string) (out0 model.MinecraftSession, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetMinecraftSession(id)
	return
}

func (r *SQLiteHTTPRepository0372) SaveMinecraftJoin(item model.MinecraftJoin) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveMinecraftJoin(item)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetMinecraftJoin(username string, serverID string) (out0 model.MinecraftJoin, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetMinecraftJoin(username, serverID)
	return
}

func (r *SQLiteHTTPRepository0372) ConsumeMinecraftJoin(username string, serverID string, expectedSessionID string, now time.Time) (out0 model.MinecraftJoin, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ConsumeMinecraftJoin(username, serverID, expectedSessionID, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetOfficialProvider02611(arg0 context.Context) (out0 OfficialProviderRevision02611, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetOfficialProvider02611(arg0)
	return
}

func (r *SQLiteHTTPRepository0372) SaveOfficialProvider02611(arg0 context.Context, expected int64, settings OfficialProviderSettings02611, actor string, reason string) (out0 OfficialProviderRevision02611, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveOfficialProvider02611(arg0, expected, settings, actor, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListOfficialProviderHistory02611(arg0 context.Context, limit int) (out0 []OfficialProviderRevision02611, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListOfficialProviderHistory02611(arg0, limit)
	return
}

func (r *SQLiteHTTPRepository0372) GetOperationalConfig(arg0 context.Context) (out0 OperationalConfigRevision, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetOperationalConfig(arg0)
	return
}

func (r *SQLiteHTTPRepository0372) ListOperationalConfigRevisions(arg0 context.Context, limit int) (out0 []OperationalConfigRevision, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListOperationalConfigRevisions(arg0, limit)
	return
}

func (r *SQLiteHTTPRepository0372) SaveOperationalConfig(arg0 context.Context, expected int64, settings OperationalConfig, actor string, reason string, restore *int64) (out0 OperationalConfigRevision, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveOperationalConfig(arg0, expected, settings, actor, reason, restore)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListProjectOperations(arg0 context.Context, projectID string, status string, limit int, offset int) (out0 []model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListProjectOperations(arg0, projectID, status, limit, offset)
	return
}

func (r *SQLiteHTTPRepository0372) CompleteOperationJob(arg0 context.Context, id string, token string, result []byte) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CompleteOperationJob(arg0, id, token, result)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) CancelOperationJob(arg0 context.Context, id string, actor string) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CancelOperationJob(arg0, id, actor)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RetryOperationJob(arg0 context.Context, id string) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RetryOperationJob(arg0, id)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListOperationAttempts(arg0 context.Context, id string) (out0 []model.DurableJobAttempt, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListOperationAttempts(arg0, id)
	return
}

func (r *SQLiteHTTPRepository0372) FindOperationByKey(arg0 context.Context, kind string, actor string, key string) (out0 model.DurableJob, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.FindOperationByKey(arg0, kind, actor, key)
	return
}

func (r *SQLiteHTTPRepository0372) CreateProfileExclusive0225(p model.Profile) (out0 model.Profile, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CreateProfileExclusive0225(p)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ActiveProtectionBan(arg0 context.Context, userID string, now time.Time) (out0 ProtectionBan, out1 bool, out2 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1, out2 = r.mem.ActiveProtectionBan(arg0, userID, now)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out2 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SetProtectionBan(arg0 context.Context, b ProtectionBan) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SetProtectionBan(arg0, b)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) RevokeProtectionBan(arg0 context.Context, userID string, actor string) (out0 bool, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.RevokeProtectionBan(arg0, userID, actor)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListProtectionBans(arg0 context.Context) (out0 []ProtectionBan, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListProtectionBans(arg0)
	return
}

func (r *SQLiteHTTPRepository0372) CreateReleaseDraft(arg0 context.Context, d ReleaseDraft) (out0 ReleaseDraft, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.CreateReleaseDraft(arg0, d)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListReleaseDrafts(arg0 context.Context, projectID string, ownerID string) (out0 []ReleaseDraft, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListReleaseDrafts(arg0, projectID, ownerID)
	return
}

func (r *SQLiteHTTPRepository0372) GetReleaseDraft(arg0 context.Context, id string) (out0 ReleaseDraft, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetReleaseDraft(arg0, id)
	return
}

func (r *SQLiteHTTPRepository0372) UpdateReleaseDraft(arg0 context.Context, d ReleaseDraft) (out0 ReleaseDraft, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.UpdateReleaseDraft(arg0, d)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) DeleteReleaseDraft(arg0 context.Context, id string, ownerID string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.DeleteReleaseDraft(arg0, id, ownerID)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveStagedRun0342(arg0 context.Context, v model.StagedRuntimeRun0342) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveStagedRun0342(arg0, v)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListStagedRuns0342(arg0 context.Context, packageID string) (out0 []model.StagedRuntimeRun0342, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListStagedRuns0342(arg0, packageID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveIntegrityCheck(ctx context.Context, result model.IntegrityCheckResult) (out0 model.IntegrityCheckResult, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveIntegrityCheck(ctx, result)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) LatestIntegrityCheck(ctx context.Context, packageID string) (out0 model.IntegrityCheckResult, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.LatestIntegrityCheck(ctx, packageID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveRuntimeValidation(ctx context.Context, result model.RuntimeValidationResult) (out0 model.RuntimeValidationResult, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveRuntimeValidation(ctx, result)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListRuntimeValidations(ctx context.Context, packageID string) (out0 []model.RuntimeValidationResult, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListRuntimeValidations(ctx, packageID)
	return
}

func (r *SQLiteHTTPRepository0372) GetProjectValidationPolicy(ctx context.Context, projectID string) (out0 model.ProjectValidationPolicy, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetProjectValidationPolicy(ctx, projectID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveProjectValidationPolicy(ctx context.Context, policy model.ProjectValidationPolicy) (out0 model.ProjectValidationPolicy, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.SaveProjectValidationPolicy(ctx, policy)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out1 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) SaveValidationAttestation0345(arg0 context.Context, v model.ValidationAttestation0345) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveValidationAttestation0345(arg0, v)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListValidationAttestations0345(arg0 context.Context, packageID string) (out0 []model.ValidationAttestation0345, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListValidationAttestations0345(arg0, packageID)
	return
}

func (r *SQLiteHTTPRepository0372) SaveValidationAttempt03412(arg0 context.Context, e model.ValidationAttempt03412) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveValidationAttempt03412(arg0, e)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) ListValidationAttempts03412(arg0 context.Context, packageID string, before int64, limit int) (out0 []model.ValidationAttempt03412, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.ListValidationAttempts03412(arg0, packageID, before, limit)
	return
}

func (r *SQLiteHTTPRepository0372) SaveValidationChallenge0346(arg0 context.Context, c model.ValidationChallenge0346) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.SaveValidationChallenge0346(arg0, c)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetValidationChallenge0346(arg0 context.Context, runID string) (out0 model.ValidationChallenge0346, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetValidationChallenge0346(arg0, runID)
	return
}

func (r *SQLiteHTTPRepository0372) IsValidationKeyRevoked0346(arg0 context.Context, fingerprint string) (out0 bool, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.IsValidationKeyRevoked0346(arg0, fingerprint)
	return
}

func (r *SQLiteHTTPRepository0372) RevokeValidationKey0346(arg0 context.Context, fingerprint string, actor string, reason string) (out0 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0 = r.mem.RevokeValidationKey0346(arg0, fingerprint, actor, reason)
	if e := r.persist(context.Background()); e != nil {
		r.failed = e
		out0 = e
	}
	return
}

func (r *SQLiteHTTPRepository0372) GetValidationRun03412(arg0 context.Context, pkg string, run string) (out0 model.StagedRuntimeRun0342, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetValidationRun03412(arg0, pkg, run)
	return
}

func (r *SQLiteHTTPRepository0372) GetValidationEvidence03412(arg0 context.Context, pkg string, run string) (out0 model.ValidationAttestation0345, out1 error) {
	r.mu.Lock()
	auditStart := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(auditStart)
	if r.failed != nil {
		panic(r.failed)
	}
	out0, out1 = r.mem.GetValidationEvidence03412(arg0, pkg, run)
	return
}

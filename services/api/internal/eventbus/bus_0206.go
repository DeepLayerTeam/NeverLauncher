package eventbus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const ProtocolVersion = "1.0"

var (
	ErrHookRejected = errors.New("extension sync hook rejected operation")
	ErrHookTimeout  = errors.New("extension sync hook timeout")
)

type EventSpec struct {
	Type               string
	CategoryPermission string
	SyncAllowed        bool
}

var specs0206 = map[string]EventSpec{
	"project.before-save":         {"project.before-save", "project:read", true},
	"project.saved":               {"project.saved", "project:read", false},
	"release.created":             {"release.created", "release:read", false},
	"release.before-publish":      {"release.before-publish", "release:read", true},
	"release.published":           {"release.published", "release:read", false},
	"package.created":             {"package.created", "release:read", false},
	"package.file-added":          {"package.file-added", "release:read", false},
	"package.validated":           {"package.validated", "release:read", false},
	"package.signed":              {"package.signed", "release:read", false},
	"package.staged":              {"package.staged", "release:read", false},
	"package.smoke-tested":        {"package.smoke-tested", "release:read", false},
	"package.before-publish":      {"package.before-publish", "release:read", true},
	"package.published":           {"package.published", "release:read", false},
	"storage.before-write":        {"storage.before-write", "storage:read", true},
	"storage.file-written":        {"storage.file-written", "storage:read", false},
	"serverbridge.event.received": {"serverbridge.event.received", "serverbridge:read", false},
	"audit.event.created":         {"audit.event.created", "audit:read", false},
}

func KnownEventTypes() []string {
	out := make([]string, 0, len(specs0206))
	for k := range specs0206 {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func Spec(eventType string) (EventSpec, bool) {
	x, ok := specs0206[strings.ToLower(strings.TrimSpace(eventType))]
	return x, ok
}

type Config struct {
	WorkerInterval time.Duration
	LeaseDuration  time.Duration
	HookTimeout    time.Duration
	MaxAttempts    int
	BaseRetry      time.Duration
	MaxRetry       time.Duration
	BatchSize      int
}

func (c Config) normalized() Config {
	if c.WorkerInterval <= 0 {
		c.WorkerInterval = 250 * time.Millisecond
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = 30 * time.Second
	}
	if c.HookTimeout <= 0 {
		c.HookTimeout = 2 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 8
	}
	if c.BaseRetry <= 0 {
		c.BaseRetry = time.Second
	}
	if c.MaxRetry <= 0 {
		c.MaxRetry = 5 * time.Minute
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 32
	}
	if c.BatchSize > 100 {
		c.BatchSize = 100
	}
	return c
}

type Dispatcher interface {
	DeliverExtensionEvent(context.Context, model.ExtensionEventSubscription, model.ExtensionEvent) error
	DeliverExtensionHook(context.Context, model.ExtensionEventSubscription, model.ExtensionEvent) (model.ExtensionHookResult, error)
}

type Bus struct {
	cfg        Config
	store      repository.ExtensionEventStore
	mu         sync.RWMutex
	dispatcher Dispatcher
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func New(cfg Config, repo repository.Repository) (*Bus, error) {
	store, ok := repo.(repository.ExtensionEventStore)
	if !ok {
		return nil, errors.New("repository does not implement durable NeverExtensions event store")
	}
	return &Bus{cfg: cfg.normalized(), store: store}, nil
}
func (b *Bus) SetDispatcher(d Dispatcher)  { b.mu.Lock(); b.dispatcher = d; b.mu.Unlock() }
func (b *Bus) dispatcherValue() Dispatcher { b.mu.RLock(); defer b.mu.RUnlock(); return b.dispatcher }
func (b *Bus) Start(ctx context.Context) {
	b.mu.Lock()
	if b.cancel != nil {
		b.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.wg.Add(1)
	b.mu.Unlock()
	go b.worker(runCtx)
}
func (b *Bus) Close() {
	b.mu.Lock()
	cancel := b.cancel
	b.cancel = nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	b.wg.Wait()
}

type PublishInput struct {
	Type, ProjectID, AggregateType, AggregateID, OrderingKey, IdempotencyKey, Source string
	Payload                                                                          any
	OccurredAt                                                                       time.Time
}

func (b *Bus) Publish(ctx context.Context, in PublishInput) (model.ExtensionEvent, bool, error) {
	event, err := buildEvent0206(in)
	if err != nil {
		return model.ExtensionEvent{}, false, err
	}
	return b.store.PublishExtensionEvent(ctx, event)
}
func buildEvent0206(in PublishInput) (model.ExtensionEvent, error) {
	t := strings.ToLower(strings.TrimSpace(in.Type))
	if _, ok := specs0206[t]; !ok {
		return model.ExtensionEvent{}, fmt.Errorf("unsupported extension event type %q", t)
	}
	raw, err := json.Marshal(in.Payload)
	if err != nil {
		return model.ExtensionEvent{}, err
	}
	id, err := randomID0206()
	if err != nil {
		return model.ExtensionEvent{}, err
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		in.IdempotencyKey = id
	}
	if strings.TrimSpace(in.OrderingKey) == "" {
		in.OrderingKey = in.AggregateType + ":" + in.AggregateID
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	return model.ExtensionEvent{ID: id, Type: t, SchemaVersion: 1, ProjectID: strings.TrimSpace(in.ProjectID), AggregateType: strings.TrimSpace(in.AggregateType), AggregateID: strings.TrimSpace(in.AggregateID), OrderingKey: strings.TrimSpace(in.OrderingKey), IdempotencyKey: strings.TrimSpace(in.IdempotencyKey), Source: strings.TrimSpace(in.Source), Payload: raw, OccurredAt: in.OccurredAt}, nil
}
func randomID0206() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "evt_" + hex.EncodeToString(b[:]), nil
}

func (b *Bus) DispatchSync(ctx context.Context, in PublishInput) error {
	spec, ok := Spec(in.Type)
	if !ok {
		return fmt.Errorf("unsupported extension event type %q", in.Type)
	}
	if !spec.SyncAllowed {
		return fmt.Errorf("event %s cannot be used as sync hook", in.Type)
	}
	event, _, err := b.Publish(ctx, in)
	if err != nil {
		return err
	}
	subs, err := b.store.ListExtensionEventSubscriptionsForType(ctx, event.Type, model.ExtensionEventModeSync)
	if err != nil {
		return err
	}
	d := b.dispatcherValue()
	if len(subs) > 0 && d == nil {
		return errors.New("sync hook dispatcher unavailable")
	}
	for _, sub := range subs {
		if sub.Scope == "project" && sub.ScopeID != event.ProjectID {
			continue
		}
		hookCtx, cancel := context.WithTimeout(ctx, b.cfg.HookTimeout)
		result, callErr := d.DeliverExtensionHook(hookCtx, sub, event)
		cancel()
		if errors.Is(callErr, context.DeadlineExceeded) || errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%w: %s/%s", ErrHookTimeout, sub.ExtensionID, event.Type)
		}
		if callErr != nil {
			return fmt.Errorf("sync hook %s/%s failed: %w", sub.ExtensionID, event.Type, callErr)
		}
		if !result.OK {
			return fmt.Errorf("%w: %s: %s", ErrHookRejected, sub.ExtensionID, strings.TrimSpace(result.Message))
		}
	}
	return nil
}

func (b *Bus) Subscribe(ctx context.Context, sub model.ExtensionEventSubscription) (model.ExtensionEventSubscription, error) {
	if _, ok := Spec(sub.EventType); !ok {
		return model.ExtensionEventSubscription{}, fmt.Errorf("unsupported extension event type %q", sub.EventType)
	}
	if sub.Mode == model.ExtensionEventModeSync {
		spec, _ := Spec(sub.EventType)
		if !spec.SyncAllowed {
			return model.ExtensionEventSubscription{}, fmt.Errorf("event %s is async-only", sub.EventType)
		}
	}
	sub.Enabled = true
	return b.store.SaveExtensionEventSubscription(ctx, sub)
}
func (b *Bus) Unsubscribe(ctx context.Context, id int64, extensionID, scope, scopeID string) error {
	return b.store.DeleteExtensionEventSubscription(ctx, id, extensionID, scope, scopeID)
}
func (b *Bus) Subscriptions(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionEventSubscription, error) {
	return b.store.ListExtensionEventSubscriptions(ctx, extensionID, scope, scopeID)
}
func (b *Bus) SetSubscriptionsEnabled(ctx context.Context, extensionID, scope, scopeID string, enabled bool) error {
	return b.store.SetExtensionEventSubscriptionsEnabled(ctx, extensionID, scope, scopeID, enabled)
}
func (b *Bus) DeadLetters(ctx context.Context, extensionID string, limit int) ([]model.ExtensionEventDeadLetter, error) {
	return b.store.ListExtensionEventDeadLetters(ctx, extensionID, limit)
}
func (b *Bus) ConfigSummary() map[string]any {
	return map[string]any{"protocolVersion": ProtocolVersion, "workerIntervalMs": b.cfg.WorkerInterval.Milliseconds(), "leaseSeconds": b.cfg.LeaseDuration.Seconds(), "hookTimeoutMs": b.cfg.HookTimeout.Milliseconds(), "maxAttempts": b.cfg.MaxAttempts, "baseRetryMs": b.cfg.BaseRetry.Milliseconds(), "maxRetrySeconds": b.cfg.MaxRetry.Seconds(), "batchSize": b.cfg.BatchSize}
}

func (b *Bus) worker(ctx context.Context) {
	defer b.wg.Done()
	ticker := time.NewTicker(b.cfg.WorkerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.processBatch(ctx)
		}
	}
}
func (b *Bus) processBatch(ctx context.Context) {
	d := b.dispatcherValue()
	if d == nil {
		return
	}
	items, err := b.store.LeaseExtensionEventDeliveries(ctx, b.cfg.BatchSize, time.Now().UTC().Add(b.cfg.LeaseDuration))
	if err != nil {
		log.Printf("NeverExtensions event lease failed: %v", err)
		return
	}
	for _, env := range items {
		deliveryCtx, cancel := context.WithTimeout(ctx, b.cfg.LeaseDuration)
		err := d.DeliverExtensionEvent(deliveryCtx, env.Subscription, env.Event)
		cancel()
		now := time.Now().UTC()
		if err == nil {
			if ackErr := b.store.CompleteExtensionEventDelivery(ctx, env.Delivery.ID, env.Delivery.LeaseToken, now); ackErr != nil {
				log.Printf("NeverExtensions event ack failed delivery=%d: %v", env.Delivery.ID, ackErr)
			}
			continue
		}
		if env.Delivery.AttemptCount >= b.cfg.MaxAttempts {
			if dlqErr := b.store.DeadLetterExtensionEventDelivery(ctx, env.Delivery.ID, env.Delivery.LeaseToken, err.Error(), now); dlqErr != nil {
				log.Printf("NeverExtensions DLQ failed delivery=%d: %v", env.Delivery.ID, dlqErr)
			}
			continue
		}
		delay := b.retryDelay(env.Delivery.AttemptCount)
		if retryErr := b.store.RetryExtensionEventDelivery(ctx, env.Delivery.ID, env.Delivery.LeaseToken, now.Add(delay), err.Error()); retryErr != nil {
			log.Printf("NeverExtensions retry scheduling failed delivery=%d: %v", env.Delivery.ID, retryErr)
		}
	}
}
func (b *Bus) retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	power := math.Min(float64(attempt-1), 10)
	d := time.Duration(float64(b.cfg.BaseRetry) * math.Pow(2, power))
	if d > b.cfg.MaxRetry {
		return b.cfg.MaxRetry
	}
	return d
}

// Typed domain payloads. They intentionally contain identifiers and immutable
// snapshots only; auth tokens, Guard/device credentials and backend secrets are
// never copied into extension events.
type ProjectPayload struct {
	Action  string        `json:"action"`
	Actor   string        `json:"actor,omitempty"`
	Project model.Project `json:"project"`
}
type ReleasePayload struct {
	Action  string               `json:"action"`
	Actor   string               `json:"actor,omitempty"`
	Release model.ReleaseVersion `json:"release"`
}
type PackagePayload struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	PackageID string `json:"packageId"`
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Version   string `json:"version,omitempty"`
	Status    string `json:"status,omitempty"`
}
type StoragePayload struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	ProjectID string `json:"projectId"`
	VersionID string `json:"versionId"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size"`
}
type ServerBridgePayload struct {
	ServerID  string                  `json:"serverId"`
	RuntimeID string                  `json:"runtimeId"`
	Event     model.ServerBridgeEvent `json:"event"`
}
type AuditPayload struct {
	Event model.AuditEvent `json:"event"`
}

func (b *Bus) BeforeProjectSave(ctx context.Context, actor, action string, p model.Project) error {
	return b.DispatchSync(ctx, PublishInput{Type: "project.before-save", ProjectID: p.ID, AggregateType: "project", AggregateID: p.ID, OrderingKey: "project:" + p.ID, IdempotencyKey: "hook:" + action + ":" + p.ID + ":" + fmt.Sprint(time.Now().UTC().UnixNano()), Source: "httpapi", Payload: ProjectPayload{Action: action, Actor: actor, Project: p}})
}
func (b *Bus) ProjectSaved(ctx context.Context, actor, action string, p model.Project) error {
	_, _, err := b.Publish(ctx, PublishInput{Type: "project.saved", ProjectID: p.ID, AggregateType: "project", AggregateID: p.ID, OrderingKey: "project:" + p.ID, IdempotencyKey: action + ":" + p.ID + ":" + p.UpdatedAt.UTC().Format(time.RFC3339Nano), Source: "httpapi", Payload: ProjectPayload{Action: action, Actor: actor, Project: p}, OccurredAt: p.UpdatedAt})
	return err
}
func (b *Bus) ReleaseCreated(ctx context.Context, actor string, r model.ReleaseVersion) error {
	_, _, err := b.Publish(ctx, PublishInput{Type: "release.created", ProjectID: r.ProjectID, AggregateType: "release", AggregateID: r.ID, OrderingKey: "release:" + r.ID, IdempotencyKey: "created:" + r.ID, Source: "httpapi", Payload: ReleasePayload{Action: "created", Actor: actor, Release: r}})
	return err
}
func (b *Bus) BeforeReleasePublish(ctx context.Context, actor string, r model.ReleaseVersion) error {
	return b.DispatchSync(ctx, PublishInput{Type: "release.before-publish", ProjectID: r.ProjectID, AggregateType: "release", AggregateID: r.ID, OrderingKey: "release:" + r.ID, IdempotencyKey: "before-publish:" + r.ID, Source: "httpapi", Payload: ReleasePayload{Action: "publish", Actor: actor, Release: r}})
}
func (b *Bus) ReleasePublished(ctx context.Context, actor string, r model.ReleaseVersion) error {
	_, _, err := b.Publish(ctx, PublishInput{Type: "release.published", ProjectID: r.ProjectID, AggregateType: "release", AggregateID: r.ID, OrderingKey: "release:" + r.ID, IdempotencyKey: "published:" + r.ID, Source: "httpapi", Payload: ReleasePayload{Action: "published", Actor: actor, Release: r}})
	return err
}
func (b *Bus) PackageEvent(ctx context.Context, eventType string, p PackagePayload) error {
	_, _, err := b.Publish(ctx, PublishInput{Type: eventType, ProjectID: p.ProjectID, AggregateType: "package", AggregateID: p.PackageID, OrderingKey: "package:" + p.PackageID, IdempotencyKey: eventType + ":" + p.PackageID + ":" + p.Status, Source: "httpapi", Payload: p})
	return err
}
func (b *Bus) BeforePackagePublish(ctx context.Context, p PackagePayload) error {
	return b.DispatchSync(ctx, PublishInput{Type: "package.before-publish", ProjectID: p.ProjectID, AggregateType: "package", AggregateID: p.PackageID, OrderingKey: "package:" + p.PackageID, IdempotencyKey: "before-publish:" + p.PackageID, Source: "httpapi", Payload: p})
}
func (b *Bus) BeforeStorageWrite(ctx context.Context, p StoragePayload) error {
	return b.DispatchSync(ctx, PublishInput{Type: "storage.before-write", ProjectID: p.ProjectID, AggregateType: "storage", AggregateID: p.ProjectID + ":" + p.VersionID + ":" + p.Path, OrderingKey: "storage:" + p.ProjectID + ":" + p.VersionID, IdempotencyKey: "before-write:" + p.ProjectID + ":" + p.VersionID + ":" + p.Path + ":" + fmt.Sprint(time.Now().UTC().UnixNano()), Source: "httpapi", Payload: p})
}
func (b *Bus) StorageWritten(ctx context.Context, p StoragePayload) error {
	_, _, err := b.Publish(ctx, PublishInput{Type: "storage.file-written", ProjectID: p.ProjectID, AggregateType: "storage", AggregateID: p.ProjectID + ":" + p.VersionID + ":" + p.Path, OrderingKey: "storage:" + p.ProjectID + ":" + p.VersionID, IdempotencyKey: "written:" + p.ProjectID + ":" + p.VersionID + ":" + p.Path + ":" + p.SHA256, Source: "httpapi", Payload: p})
	return err
}
func (b *Bus) ServerBridgeReceived(ctx context.Context, serverID, runtimeID string, e model.ServerBridgeEvent) error {
	_, _, err := b.Publish(ctx, PublishInput{Type: "serverbridge.event.received", AggregateType: "serverbridge", AggregateID: serverID, OrderingKey: "serverbridge:" + serverID + ":" + runtimeID, IdempotencyKey: "bridge:" + serverID + ":" + e.EventID, Source: "serverbridge", Payload: ServerBridgePayload{ServerID: serverID, RuntimeID: runtimeID, Event: e}, OccurredAt: time.UnixMilli(e.OccurredAtUnixMillis).UTC()})
	return err
}
func (b *Bus) AuditCreated(ctx context.Context, e model.AuditEvent) error {
	id := e.ID
	if id == "" {
		id = e.Action + ":" + e.Target + ":" + e.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	_, _, err := b.Publish(ctx, PublishInput{Type: "audit.event.created", AggregateType: "audit", AggregateID: id, OrderingKey: "audit", IdempotencyKey: "audit:" + id, Source: "audit", Payload: AuditPayload{Event: e}, OccurredAt: e.CreatedAt})
	return err
}

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
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// ExtensionEventStore is the persistence boundary used by the 0.20.6 event bus.
// SQLRepository implements it with durable PostgreSQL state; MemoryRepository
// exists for tests/development with equivalent ordering/idempotency semantics.
type ExtensionEventStore interface {
	PublishExtensionEvent(context.Context, model.ExtensionEvent) (model.ExtensionEvent, bool, error)
	SaveExtensionEventSubscription(context.Context, model.ExtensionEventSubscription) (model.ExtensionEventSubscription, error)
	DeleteExtensionEventSubscription(context.Context, int64, string, string, string) error
	SetExtensionEventSubscriptionsEnabled(context.Context, string, string, string, bool) error
	ListExtensionEventSubscriptions(context.Context, string, string, string) ([]model.ExtensionEventSubscription, error)
	ListExtensionEventSubscriptionsForType(context.Context, string, string) ([]model.ExtensionEventSubscription, error)
	LeaseExtensionEventDeliveries(context.Context, int, time.Time) ([]model.ExtensionEventDeliveryEnvelope, error)
	CompleteExtensionEventDelivery(context.Context, int64, string, time.Time) error
	RetryExtensionEventDelivery(context.Context, int64, string, time.Time, string) error
	DeadLetterExtensionEventDelivery(context.Context, int64, string, string, time.Time) error
	ListExtensionEventDeadLetters(context.Context, string, int) ([]model.ExtensionEventDeadLetter, error)
}

func newEventLeaseToken0206() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate event delivery lease token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func normalizeEvent0206(in model.ExtensionEvent) (model.ExtensionEvent, error) {
	in.ID = strings.ToLower(strings.TrimSpace(in.ID))
	in.Type = strings.ToLower(strings.TrimSpace(in.Type))
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.AggregateType = strings.ToLower(strings.TrimSpace(in.AggregateType))
	in.AggregateID = strings.TrimSpace(in.AggregateID)
	in.OrderingKey = strings.TrimSpace(in.OrderingKey)
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	in.Source = strings.ToLower(strings.TrimSpace(in.Source))
	if in.SchemaVersion == 0 {
		in.SchemaVersion = 1
	}
	if in.ID == "" || in.Type == "" || in.AggregateType == "" || in.AggregateID == "" || in.OrderingKey == "" || in.IdempotencyKey == "" || in.Source == "" {
		return model.ExtensionEvent{}, errors.New("extension event identity/type/aggregate/ordering/idempotency/source are required")
	}
	if len(in.ID) > 128 || len(in.Type) > 128 || len(in.OrderingKey) > 256 || len(in.IdempotencyKey) > 256 || len(in.AggregateID) > 256 || len(in.Source) > 128 {
		return model.ExtensionEvent{}, errors.New("extension event metadata exceeds limits")
	}
	if in.SchemaVersion < 1 {
		return model.ExtensionEvent{}, errors.New("extension event schemaVersion must be positive")
	}
	var payload any
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(strings.NewReader(string(in.Payload)))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return model.ExtensionEvent{}, fmt.Errorf("invalid extension event payload: %w", err)
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return model.ExtensionEvent{}, err
	}
	if len(canonical) > 1<<20 {
		return model.ExtensionEvent{}, errors.New("extension event payload exceeds 1 MiB")
	}
	in.Payload = canonical
	sum := sha256.Sum256(canonical)
	in.PayloadSHA256 = hex.EncodeToString(sum[:])
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	in.OccurredAt = in.OccurredAt.UTC()
	return in, nil
}

func normalizeSubscription0206(in model.ExtensionEventSubscription) (model.ExtensionEventSubscription, error) {
	in.ExtensionID = strings.ToLower(strings.TrimSpace(in.ExtensionID))
	in.Scope = strings.ToLower(strings.TrimSpace(in.Scope))
	in.ScopeID = strings.TrimSpace(in.ScopeID)
	in.EventType = strings.ToLower(strings.TrimSpace(in.EventType))
	in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	if in.Scope == "" {
		in.Scope = "global"
	}
	if in.Scope == "global" {
		in.ScopeID = ""
	}
	if !extensionID0201.MatchString(in.ExtensionID) {
		return model.ExtensionEventSubscription{}, fmt.Errorf("invalid extension id %q", in.ExtensionID)
	}
	if in.Scope != "global" && in.Scope != "project" {
		return model.ExtensionEventSubscription{}, errors.New("subscription scope must be global or project")
	}
	if in.Scope == "project" && in.ScopeID == "" {
		return model.ExtensionEventSubscription{}, errors.New("project subscription requires scopeId")
	}
	if !extensionPermission0201.MatchString(in.EventType) {
		return model.ExtensionEventSubscription{}, fmt.Errorf("invalid event type %q", in.EventType)
	}
	if in.Mode != model.ExtensionEventModeAsync && in.Mode != model.ExtensionEventModeSync {
		return model.ExtensionEventSubscription{}, errors.New("subscription mode must be async or sync")
	}
	return in, nil
}

func (r *MemoryRepository) PublishExtensionEvent(ctx context.Context, in model.ExtensionEvent) (model.ExtensionEvent, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionEvent{}, false, err
	}
	in, err := normalizeEvent0206(in)
	if err != nil {
		return model.ExtensionEvent{}, false, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, existing := range r.extensionEvents {
		if existing.Type == in.Type && existing.IdempotencyKey == in.IdempotencyKey {
			if existing.PayloadSHA256 != in.PayloadSHA256 || existing.AggregateID != in.AggregateID || existing.OrderingKey != in.OrderingKey {
				return model.ExtensionEvent{}, false, fmt.Errorf("%w: event idempotency key reused with different content", ErrConflict)
			}
			return existing, false, nil
		}
		if existing.ID == in.ID {
			return model.ExtensionEvent{}, false, fmt.Errorf("%w: duplicate event id", ErrConflict)
		}
	}
	r.nextExtensionEventSequence++
	in.Sequence = r.nextExtensionEventSequence
	in.CreatedAt = time.Now().UTC()
	r.extensionEvents = append(r.extensionEvents, in)
	for _, sub := range r.extensionEventSubscriptions {
		if sub.Enabled && sub.Mode == model.ExtensionEventModeAsync && sub.EventType == in.Type && eventMatchesSubscriptionScope0206(in, sub) {
			r.nextExtensionDeliveryID++
			now := time.Now().UTC()
			r.extensionEventDeliveries = append(r.extensionEventDeliveries, model.ExtensionEventDelivery{ID: r.nextExtensionDeliveryID, EventSequence: in.Sequence, SubscriptionID: sub.ID, Status: "pending", NextAttemptAt: now, CreatedAt: now, UpdatedAt: now})
		}
	}
	return in, true, nil
}

func eventMatchesSubscriptionScope0206(event model.ExtensionEvent, sub model.ExtensionEventSubscription) bool {
	return sub.Scope == "global" || (sub.Scope == "project" && event.ProjectID != "" && event.ProjectID == sub.ScopeID)
}

func (r *MemoryRepository) SaveExtensionEventSubscription(ctx context.Context, in model.ExtensionEventSubscription) (model.ExtensionEventSubscription, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionEventSubscription{}, err
	}
	in, err := normalizeSubscription0206(in)
	if err != nil {
		return model.ExtensionEventSubscription{}, err
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	existsExtension := false
	for _, ext := range r.extensions {
		if ext.ID == in.ExtensionID {
			existsExtension = true
			break
		}
	}
	if !existsExtension {
		return model.ExtensionEventSubscription{}, ErrNotFound
	}
	for i := range r.extensionEventSubscriptions {
		x := &r.extensionEventSubscriptions[i]
		if x.ExtensionID == in.ExtensionID && x.Scope == in.Scope && x.ScopeID == in.ScopeID && x.EventType == in.EventType && x.Mode == in.Mode {
			x.Enabled = in.Enabled
			x.UpdatedAt = now
			return *x, nil
		}
	}
	r.nextExtensionSubscriptionID++
	in.ID = r.nextExtensionSubscriptionID
	in.CreatedAt = now
	in.UpdatedAt = now
	r.extensionEventSubscriptions = append(r.extensionEventSubscriptions, in)
	return in, nil
}

func (r *MemoryRepository) DeleteExtensionEventSubscription(ctx context.Context, id int64, extensionID, scope, scopeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i, x := range r.extensionEventSubscriptions {
		if x.ID == id && x.ExtensionID == extensionID && x.Scope == scope && x.ScopeID == scopeID {
			r.extensionEventSubscriptions = append(r.extensionEventSubscriptions[:i], r.extensionEventSubscriptions[i+1:]...)
			kept := r.extensionEventDeliveries[:0]
			for _, d := range r.extensionEventDeliveries {
				if d.SubscriptionID != id {
					kept = append(kept, d)
				}
			}
			r.extensionEventDeliveries = kept
			return nil
		}
	}
	return ErrNotFound
}
func (r *MemoryRepository) SetExtensionEventSubscriptionsEnabled(ctx context.Context, extensionID, scope, scopeID string, enabled bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	now := time.Now().UTC()
	for i := range r.extensionEventSubscriptions {
		x := &r.extensionEventSubscriptions[i]
		if x.ExtensionID == extensionID && x.Scope == scope && x.ScopeID == scopeID {
			x.Enabled = enabled
			x.UpdatedAt = now
		}
	}
	return nil
}

func (r *MemoryRepository) ListExtensionEventSubscriptions(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionEventSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionEventSubscription{}
	for _, x := range r.extensionEventSubscriptions {
		if (extensionID == "" || x.ExtensionID == extensionID) && (scope == "" || x.Scope == scope) && (scopeID == "" || x.ScopeID == scopeID) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (r *MemoryRepository) ListExtensionEventSubscriptionsForType(ctx context.Context, eventType, mode string) ([]model.ExtensionEventSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionEventSubscription{}
	installEnabled := func(sub model.ExtensionEventSubscription) bool {
		for _, install := range r.extensionInstalls {
			if install.ExtensionID == sub.ExtensionID && install.Scope == sub.Scope && install.ScopeID == sub.ScopeID {
				return install.Enabled && install.CurrentState == model.ExtensionInstallStateEnabled
			}
		}
		return false
	}
	for _, x := range r.extensionEventSubscriptions {
		if x.Enabled && x.EventType == eventType && x.Mode == mode && installEnabled(x) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (r *MemoryRepository) LeaseExtensionEventDeliveries(ctx context.Context, limit int, leaseUntil time.Time) ([]model.ExtensionEventDeliveryEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 {
		limit = 1
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionEventDeliveryEnvelope{}
	findEvent := func(seq int64) (model.ExtensionEvent, bool) {
		for _, e := range r.extensionEvents {
			if e.Sequence == seq {
				return e, true
			}
		}
		return model.ExtensionEvent{}, false
	}
	findSub := func(id int64) (model.ExtensionEventSubscription, bool) {
		for _, s := range r.extensionEventSubscriptions {
			if s.ID == id {
				return s, true
			}
		}
		return model.ExtensionEventSubscription{}, false
	}
	for i := range r.extensionEventDeliveries {
		if len(out) >= limit {
			break
		}
		d := &r.extensionEventDeliveries[i]
		ready := (d.Status == "pending" || d.Status == "retry") && !d.NextAttemptAt.After(now) || (d.Status == "processing" && d.LeaseUntil != nil && d.LeaseUntil.Before(now))
		if !ready {
			continue
		}
		e, ok := findEvent(d.EventSequence)
		if !ok {
			continue
		}
		sub, ok := findSub(d.SubscriptionID)
		if !ok || !sub.Enabled {
			continue
		}
		installEnabled := false
		for _, install := range r.extensionInstalls {
			if install.ExtensionID == sub.ExtensionID && install.Scope == sub.Scope && install.ScopeID == sub.ScopeID {
				installEnabled = install.Enabled && install.CurrentState == model.ExtensionInstallStateEnabled
				break
			}
		}
		if !installEnabled {
			continue
		}
		blocked := false
		for _, prior := range r.extensionEventDeliveries {
			if prior.SubscriptionID != d.SubscriptionID || prior.EventSequence >= d.EventSequence || prior.Status == "delivered" || prior.Status == "dead" {
				continue
			}
			pe, pok := findEvent(prior.EventSequence)
			if pok && pe.OrderingKey == e.OrderingKey {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		leaseToken, err := newEventLeaseToken0206()
		if err != nil {
			return nil, err
		}
		d.Status = "processing"
		d.AttemptCount++
		lu := leaseUntil.UTC()
		d.LeaseUntil = &lu
		d.LeaseToken = leaseToken
		d.UpdatedAt = now
		out = append(out, model.ExtensionEventDeliveryEnvelope{Delivery: *d, Event: e, Subscription: sub})
	}
	return out, nil
}
func (r *MemoryRepository) CompleteExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, when time.Time) error {
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionEventDeliveries {
		d := &r.extensionEventDeliveries[i]
		if d.ID == id {
			if d.Status != "processing" || leaseToken == "" || d.LeaseToken != leaseToken {
				return ErrConflict
			}
			d.Status = "delivered"
			t := when.UTC()
			d.DeliveredAt = &t
			d.LeaseUntil = nil
			d.LeaseToken = ""
			d.LastError = ""
			d.UpdatedAt = t
			return nil
		}
	}
	return ErrNotFound
}
func (r *MemoryRepository) RetryExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, next time.Time, msg string) error {
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionEventDeliveries {
		d := &r.extensionEventDeliveries[i]
		if d.ID == id {
			if d.Status != "processing" || leaseToken == "" || d.LeaseToken != leaseToken {
				return ErrConflict
			}
			d.Status = "retry"
			d.NextAttemptAt = next.UTC()
			d.LeaseUntil = nil
			d.LeaseToken = ""
			d.LastError = msg
			d.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return ErrNotFound
}
func (r *MemoryRepository) DeadLetterExtensionEventDelivery(ctx context.Context, id int64, leaseToken, msg string, when time.Time) error {
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionEventDeliveries {
		d := &r.extensionEventDeliveries[i]
		if d.ID != id {
			continue
		}
		if d.Status != "processing" || leaseToken == "" || d.LeaseToken != leaseToken {
			return ErrConflict
		}
		var e model.ExtensionEvent
		for _, x := range r.extensionEvents {
			if x.Sequence == d.EventSequence {
				e = x
				break
			}
		}
		var s model.ExtensionEventSubscription
		for _, x := range r.extensionEventSubscriptions {
			if x.ID == d.SubscriptionID {
				s = x
				break
			}
		}
		d.Status = "dead"
		d.LeaseUntil = nil
		d.LeaseToken = ""
		d.LastError = msg
		d.UpdatedAt = when.UTC()
		r.nextExtensionDeadLetterID++
		r.extensionEventDeadLetters = append(r.extensionEventDeadLetters, model.ExtensionEventDeadLetter{ID: r.nextExtensionDeadLetterID, DeliveryID: d.ID, EventSequence: d.EventSequence, SubscriptionID: d.SubscriptionID, ExtensionID: s.ExtensionID, EventType: e.Type, Attempts: d.AttemptCount, LastError: msg, Event: e, DeadAt: when.UTC()})
		return nil
	}
	return ErrNotFound
}
func (r *MemoryRepository) ListExtensionEventDeadLetters(ctx context.Context, extensionID string, limit int) ([]model.ExtensionEventDeadLetter, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionEventDeadLetter{}
	for i := len(r.extensionEventDeadLetters) - 1; i >= 0 && len(out) < limit; i-- {
		x := r.extensionEventDeadLetters[i]
		if extensionID == "" || x.ExtensionID == extensionID {
			out = append(out, x)
		}
	}
	return out, nil
}

// SQL implementation.
func (r *SQLRepository) PublishExtensionEvent(ctx context.Context, in model.ExtensionEvent) (model.ExtensionEvent, bool, error) {
	if err := r.check(); err != nil {
		return model.ExtensionEvent{}, false, err
	}
	in, err := normalizeEvent0206(in)
	if err != nil {
		return model.ExtensionEvent{}, false, err
	}
	desiredPayloadSHA, desiredAggregateID, desiredOrderingKey := in.PayloadSHA256, in.AggregateID, in.OrderingKey
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.ExtensionEvent{}, false, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	row := tx.QueryRowContext(ctx, `INSERT INTO extension_event_log(event_id,event_type,schema_version,project_id,aggregate_type,aggregate_id,ordering_key,idempotency_key,source,payload,payload_sha256,occurred_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13) ON CONFLICT(event_type,idempotency_key) DO NOTHING RETURNING sequence,created_at`, in.ID, in.Type, in.SchemaVersion, in.ProjectID, in.AggregateType, in.AggregateID, in.OrderingKey, in.IdempotencyKey, in.Source, string(in.Payload), in.PayloadSHA256, in.OccurredAt, now)
	inserted := true
	if err = row.Scan(&in.Sequence, &in.CreatedAt); errors.Is(err, sql.ErrNoRows) {
		inserted = false
		var payload string
		err = tx.QueryRowContext(ctx, `SELECT sequence,event_id,schema_version,project_id,aggregate_type,aggregate_id,ordering_key,source,payload::text,payload_sha256,occurred_at,created_at FROM extension_event_log WHERE event_type=$1 AND idempotency_key=$2`, in.Type, in.IdempotencyKey).Scan(&in.Sequence, &in.ID, &in.SchemaVersion, &in.ProjectID, &in.AggregateType, &in.AggregateID, &in.OrderingKey, &in.Source, &payload, &in.PayloadSHA256, &in.OccurredAt, &in.CreatedAt)
		in.Payload = json.RawMessage(payload)
		if err != nil {
			return model.ExtensionEvent{}, false, err
		}
		if in.PayloadSHA256 != desiredPayloadSHA || in.AggregateID != desiredAggregateID || in.OrderingKey != desiredOrderingKey {
			return model.ExtensionEvent{}, false, fmt.Errorf("%w: event idempotency key reused with different content", ErrConflict)
		}
	} else if err != nil {
		return model.ExtensionEvent{}, false, err
	}
	if inserted {
		_, err = tx.ExecContext(ctx, `INSERT INTO extension_event_deliveries(event_sequence,subscription_id,status,attempt_count,next_attempt_at,created_at,updated_at) SELECT $1,s.id,'pending',0,$2,$2,$2 FROM extension_event_subscriptions s WHERE s.enabled=TRUE AND s.mode='async' AND s.event_type=$3 AND (s.scope='global' OR (s.scope='project' AND s.scope_id=$4)) ON CONFLICT DO NOTHING`, in.Sequence, now, in.Type, in.ProjectID)
		if err != nil {
			return model.ExtensionEvent{}, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return model.ExtensionEvent{}, false, err
	}
	return in, inserted, nil
}

func scanSubscription0206(scanner interface{ Scan(...any) error }) (model.ExtensionEventSubscription, error) {
	var x model.ExtensionEventSubscription
	err := scanner.Scan(&x.ID, &x.ExtensionID, &x.Scope, &x.ScopeID, &x.EventType, &x.Mode, &x.Enabled, &x.CreatedAt, &x.UpdatedAt)
	return x, err
}
func (r *SQLRepository) SaveExtensionEventSubscription(ctx context.Context, in model.ExtensionEventSubscription) (model.ExtensionEventSubscription, error) {
	if err := r.check(); err != nil {
		return model.ExtensionEventSubscription{}, err
	}
	in, err := normalizeSubscription0206(in)
	if err != nil {
		return model.ExtensionEventSubscription{}, err
	}
	return scanSubscription0206(r.db.QueryRowContext(ctx, `INSERT INTO extension_event_subscriptions(extension_id,scope,scope_id,event_type,mode,enabled) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(extension_id,scope,scope_id,event_type,mode) DO UPDATE SET enabled=EXCLUDED.enabled,updated_at=now() RETURNING id,extension_id,scope,scope_id,event_type,mode,enabled,created_at,updated_at`, in.ExtensionID, in.Scope, in.ScopeID, in.EventType, in.Mode, in.Enabled))
}
func (r *SQLRepository) DeleteExtensionEventSubscription(ctx context.Context, id int64, extensionID, scope, scopeID string) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM extension_event_subscriptions WHERE id=$1 AND extension_id=$2 AND scope=$3 AND scope_id=$4`, id, extensionID, scope, scopeID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (r *SQLRepository) SetExtensionEventSubscriptionsEnabled(ctx context.Context, extensionID, scope, scopeID string, enabled bool) error {
	if err := r.check(); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE extension_event_subscriptions SET enabled=$4,updated_at=now() WHERE extension_id=$1 AND scope=$2 AND scope_id=$3`, extensionID, scope, scopeID, enabled)
	return err
}

func (r *SQLRepository) ListExtensionEventSubscriptions(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionEventSubscription, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,extension_id,scope,scope_id,event_type,mode,enabled,created_at,updated_at FROM extension_event_subscriptions WHERE ($1='' OR extension_id=$1) AND ($2='' OR scope=$2) AND ($3='' OR scope_id=$3) ORDER BY id`, extensionID, scope, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionEventSubscription{}
	for rows.Next() {
		x, e := scanSubscription0206(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *SQLRepository) ListExtensionEventSubscriptionsForType(ctx context.Context, eventType, mode string) ([]model.ExtensionEventSubscription, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT s.id,s.extension_id,s.scope,s.scope_id,s.event_type,s.mode,s.enabled,s.created_at,s.updated_at FROM extension_event_subscriptions s JOIN extension_installs i ON i.extension_id=s.extension_id AND i.scope=s.scope AND i.scope_id=s.scope_id AND i.current_state='enabled' AND i.enabled=TRUE WHERE s.enabled=TRUE AND s.event_type=$1 AND s.mode=$2 ORDER BY s.id`, eventType, mode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionEventSubscription{}
	for rows.Next() {
		x, e := scanSubscription0206(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *SQLRepository) LeaseExtensionEventDeliveries(ctx context.Context, limit int, leaseUntil time.Time) ([]model.ExtensionEventDeliveryEnvelope, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	rows, err := tx.QueryContext(ctx, `SELECT d.id FROM extension_event_deliveries d JOIN extension_event_log e ON e.sequence=d.event_sequence JOIN extension_event_subscriptions s ON s.id=d.subscription_id JOIN extension_installs i ON i.extension_id=s.extension_id AND i.scope=s.scope AND i.scope_id=s.scope_id AND i.current_state='enabled' AND i.enabled=TRUE WHERE s.enabled=TRUE AND ((d.status IN ('pending','retry') AND d.next_attempt_at <= $1) OR (d.status='processing' AND d.lease_until < $1)) AND NOT EXISTS (SELECT 1 FROM extension_event_deliveries p JOIN extension_event_log pe ON pe.sequence=p.event_sequence WHERE p.subscription_id=d.subscription_id AND pe.ordering_key=e.ordering_key AND pe.sequence<e.sequence AND p.status NOT IN ('delivered','dead')) ORDER BY e.sequence,d.subscription_id FOR UPDATE OF d SKIP LOCKED LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []model.ExtensionEventDeliveryEnvelope{}
	for _, id := range ids {
		leaseToken, tokenErr := newEventLeaseToken0206()
		if tokenErr != nil {
			return nil, tokenErr
		}
		_, err = tx.ExecContext(ctx, `UPDATE extension_event_deliveries SET status='processing',attempt_count=attempt_count+1,lease_until=$2,lease_token=$3,updated_at=$1 WHERE id=$4`, now, leaseUntil.UTC(), leaseToken, id)
		if err != nil {
			return nil, err
		}
		var env model.ExtensionEventDeliveryEnvelope
		var payload string
		var lease sql.NullTime
		var delivered sql.NullTime
		err = tx.QueryRowContext(ctx, `SELECT d.id,d.event_sequence,d.subscription_id,d.status,d.attempt_count,d.next_attempt_at,d.lease_until,d.lease_token,d.last_error,d.delivered_at,d.created_at,d.updated_at,e.sequence,e.event_id,e.event_type,e.schema_version,e.project_id,e.aggregate_type,e.aggregate_id,e.ordering_key,e.idempotency_key,e.source,e.payload::text,e.payload_sha256,e.occurred_at,e.created_at,s.id,s.extension_id,s.scope,s.scope_id,s.event_type,s.mode,s.enabled,s.created_at,s.updated_at FROM extension_event_deliveries d JOIN extension_event_log e ON e.sequence=d.event_sequence JOIN extension_event_subscriptions s ON s.id=d.subscription_id WHERE d.id=$1`, id).Scan(&env.Delivery.ID, &env.Delivery.EventSequence, &env.Delivery.SubscriptionID, &env.Delivery.Status, &env.Delivery.AttemptCount, &env.Delivery.NextAttemptAt, &lease, &env.Delivery.LeaseToken, &env.Delivery.LastError, &delivered, &env.Delivery.CreatedAt, &env.Delivery.UpdatedAt, &env.Event.Sequence, &env.Event.ID, &env.Event.Type, &env.Event.SchemaVersion, &env.Event.ProjectID, &env.Event.AggregateType, &env.Event.AggregateID, &env.Event.OrderingKey, &env.Event.IdempotencyKey, &env.Event.Source, &payload, &env.Event.PayloadSHA256, &env.Event.OccurredAt, &env.Event.CreatedAt, &env.Subscription.ID, &env.Subscription.ExtensionID, &env.Subscription.Scope, &env.Subscription.ScopeID, &env.Subscription.EventType, &env.Subscription.Mode, &env.Subscription.Enabled, &env.Subscription.CreatedAt, &env.Subscription.UpdatedAt)
		if err != nil {
			return nil, err
		}
		env.Event.Payload = json.RawMessage(payload)
		if lease.Valid {
			t := lease.Time
			env.Delivery.LeaseUntil = &t
		}
		if delivered.Valid {
			t := delivered.Time
			env.Delivery.DeliveredAt = &t
		}
		out = append(out, env)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
func (r *SQLRepository) CompleteExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, when time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE extension_event_deliveries SET status='delivered',delivered_at=$3,lease_until=NULL,lease_token='',last_error='',updated_at=$3 WHERE id=$1 AND status='processing' AND lease_token=$2`, id, leaseToken, when.UTC())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrConflict
	}
	return nil
}
func (r *SQLRepository) RetryExtensionEventDelivery(ctx context.Context, id int64, leaseToken string, next time.Time, msg string) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE extension_event_deliveries SET status='retry',next_attempt_at=$3,lease_until=NULL,lease_token='',last_error=$4,updated_at=now() WHERE id=$1 AND status='processing' AND lease_token=$2`, id, leaseToken, next.UTC(), truncateEventError0206(msg))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrConflict
	}
	return nil
}
func (r *SQLRepository) DeadLetterExtensionEventDelivery(ctx context.Context, id int64, leaseToken, msg string, when time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var seq, subID int64
	var attempts int
	var extID, eventType, payload string
	err = tx.QueryRowContext(ctx, `SELECT d.event_sequence,d.subscription_id,d.attempt_count,s.extension_id,e.event_type,jsonb_build_object('sequence',e.sequence,'id',e.event_id,'type',e.event_type,'schemaVersion',e.schema_version,'projectId',e.project_id,'aggregateType',e.aggregate_type,'aggregateId',e.aggregate_id,'orderingKey',e.ordering_key,'idempotencyKey',e.idempotency_key,'source',e.source,'payload',e.payload,'payloadSha256',e.payload_sha256,'occurredAt',e.occurred_at,'createdAt',e.created_at)::text FROM extension_event_deliveries d JOIN extension_event_subscriptions s ON s.id=d.subscription_id JOIN extension_event_log e ON e.sequence=d.event_sequence WHERE d.id=$1 AND d.status='processing' AND d.lease_token=$2 FOR UPDATE`, id, leaseToken).Scan(&seq, &subID, &attempts, &extID, &eventType, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	msg = truncateEventError0206(msg)
	_, err = tx.ExecContext(ctx, `INSERT INTO extension_event_dead_letters(delivery_id,event_sequence,subscription_id,extension_id,event_type,attempts,last_error,event_snapshot,dead_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9) ON CONFLICT(delivery_id) DO NOTHING`, id, seq, subID, extID, eventType, attempts, msg, payload, when.UTC())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE extension_event_deliveries SET status='dead',lease_until=NULL,lease_token='',last_error=$3,updated_at=$4 WHERE id=$1 AND status='processing' AND lease_token=$2`, id, leaseToken, msg, when.UTC())
	if err != nil {
		return err
	}
	return tx.Commit()
}
func truncateEventError0206(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 4096 {
		return s[:4096]
	}
	return s
}
func (r *SQLRepository) ListExtensionEventDeadLetters(ctx context.Context, extensionID string, limit int) ([]model.ExtensionEventDeadLetter, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,delivery_id,event_sequence,subscription_id,extension_id,event_type,attempts,last_error,event_snapshot::text,dead_at FROM extension_event_dead_letters WHERE ($1='' OR extension_id=$1) ORDER BY dead_at DESC LIMIT $2`, extensionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionEventDeadLetter{}
	for rows.Next() {
		var x model.ExtensionEventDeadLetter
		var raw string
		if err := rows.Scan(&x.ID, &x.DeliveryID, &x.EventSequence, &x.SubscriptionID, &x.ExtensionID, &x.EventType, &x.Attempts, &x.LastError, &raw, &x.DeadAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &x.Event); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ManagedProviderRevision02910 contains only non-secret settings. Credentials must
// reference pre-provisioned environment variables, never inline values.
type ManagedProviderRevision02910 struct {
	ID        string          `json:"id"`
	Revision  int64           `json:"revision"`
	Kind      string          `json:"kind"`
	Config    json.RawMessage `json:"config"`
	Actor     string          `json:"actor"`
	Reason    string          `json:"reason"`
	CreatedAt time.Time       `json:"createdAt"`
}
type ManagedProviderHead02910 struct {
	ID             string                         `json:"id"`
	ActiveRevision int64                          `json:"activeRevision"`
	Revisions      []ManagedProviderRevision02910 `json:"revisions,omitempty"`
}
type ManagedProviderStore02910 interface {
	ListManagedProviders02910(context.Context) ([]ManagedProviderHead02910, error)
	SaveManagedProviderDraft02910(context.Context, ManagedProviderRevision02910) (ManagedProviderRevision02910, error)
	ActivateManagedProvider02910(context.Context, string, int64, int64, string, string) (ManagedProviderHead02910, error)
}

var ErrManagedProviderConflict02910 = errors.New("managed auth provider revision conflict")
var ErrManagedProviderMissing02910 = errors.New("managed auth provider revision not found")

// SQL methods operate in transactions and serialize activations on the head row.
func (r *SQLRepository) ListManagedProviders02910(ctx context.Context) ([]ManagedProviderHead02910, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT h.provider_id,h.active_revision,v.revision,v.kind,v.config,v.actor,v.reason,v.created_at
 FROM auth_provider_heads_02910 h LEFT JOIN auth_provider_revisions_02910 v ON v.provider_id=h.provider_id ORDER BY h.provider_id,v.revision DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagedProviderHead02910
	for rows.Next() {
		var id string
		var active int64
		var rev sql.NullInt64
		var kind, actor, reason sql.NullString
		var cfg []byte
		var created sql.NullTime
		if err := rows.Scan(&id, &active, &rev, &kind, &cfg, &actor, &reason, &created); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].ID != id {
			out = append(out, ManagedProviderHead02910{ID: id, ActiveRevision: active, Revisions: []ManagedProviderRevision02910{}})
		}
		if rev.Valid {
			out[len(out)-1].Revisions = append(out[len(out)-1].Revisions, ManagedProviderRevision02910{ID: id, Revision: rev.Int64, Kind: kind.String, Config: json.RawMessage(cfg), Actor: actor.String, Reason: reason.String, CreatedAt: created.Time})
		}
	}
	return out, rows.Err()
}
func (r *SQLRepository) SaveManagedProviderDraft02910(ctx context.Context, v ManagedProviderRevision02910) (ManagedProviderRevision02910, error) {
	if err := r.check(); err != nil {
		return v, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_provider_heads_02910(provider_id,active_revision) VALUES($1,0) ON CONFLICT DO NOTHING`, v.ID); err != nil {
		return v, err
	}
	// Serialise writers by locking the same head row before assigning a revision.
	var active int64
	if err = tx.QueryRowContext(ctx, `SELECT active_revision FROM auth_provider_heads_02910 WHERE provider_id=$1 FOR UPDATE`, v.ID).Scan(&active); err != nil {
		return v, err
	}
	var latest int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0) FROM auth_provider_revisions_02910 WHERE provider_id=$1`, v.ID).Scan(&latest); err != nil {
		return v, err
	}
	v.Revision = latest + 1
	v.CreatedAt = time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_provider_revisions_02910(provider_id,revision,kind,config,actor,reason,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, v.ID, v.Revision, v.Kind, []byte(v.Config), v.Actor, v.Reason, v.CreatedAt)
	if err != nil {
		return v, err
	}
	return v, tx.Commit()
}
func (r *SQLRepository) ActivateManagedProvider02910(ctx context.Context, id string, target, expected int64, actor, reason string) (ManagedProviderHead02910, error) {
	var head ManagedProviderHead02910
	if err := r.check(); err != nil {
		return head, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return head, err
	}
	defer tx.Rollback()
	var active int64
	err = tx.QueryRowContext(ctx, `SELECT active_revision FROM auth_provider_heads_02910 WHERE provider_id=$1 FOR UPDATE`, id).Scan(&active)
	if err == sql.ErrNoRows {
		return head, ErrManagedProviderMissing02910
	}
	if err != nil {
		return head, err
	}
	if active != expected {
		return head, ErrManagedProviderConflict02910
	}
	if target != 0 {
		var exists bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM auth_provider_revisions_02910 WHERE provider_id=$1 AND revision=$2)`, id, target).Scan(&exists)
		if err != nil {
			return head, err
		}
		if !exists {
			return head, ErrManagedProviderMissing02910
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE auth_provider_heads_02910 SET active_revision=$2 WHERE provider_id=$1`, id, target); err != nil {
		return head, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_provider_activation_audit_02910(provider_id,from_revision,to_revision,actor,reason) VALUES($1,$2,$3,$4,$5)`, id, active, target, actor, reason); err != nil {
		return head, err
	}
	if err = tx.Commit(); err != nil {
		return head, err
	}
	return ManagedProviderHead02910{ID: id, ActiveRevision: target}, nil
}

// Memory mode has identical revision semantics, useful in single-node dev.

func (r *MemoryRepository) ListManagedProviders02910(_ context.Context) ([]ManagedProviderHead02910, error) {
	r.managedProviderMu.Lock()
	defer r.managedProviderMu.Unlock()
	out := make([]ManagedProviderHead02910, 0, len(r.managedProviders))
	for _, h := range r.managedProviders {
		copyH := h
		copyH.Revisions = append([]ManagedProviderRevision02910(nil), h.Revisions...)
		out = append(out, copyH)
	}
	return out, nil
}
func (r *MemoryRepository) SaveManagedProviderDraft02910(_ context.Context, v ManagedProviderRevision02910) (ManagedProviderRevision02910, error) {
	r.managedProviderMu.Lock()
	defer r.managedProviderMu.Unlock()
	if r.managedProviders == nil {
		r.managedProviders = map[string]ManagedProviderHead02910{}
	}
	h := r.managedProviders[v.ID]
	h.ID = v.ID
	v.Revision = int64(len(h.Revisions)) + 1
	v.CreatedAt = time.Now().UTC()
	h.Revisions = append(h.Revisions, v)
	r.managedProviders[v.ID] = h
	return v, nil
}
func (r *MemoryRepository) ActivateManagedProvider02910(_ context.Context, id string, target, expected int64, actor, reason string) (ManagedProviderHead02910, error) {
	r.managedProviderMu.Lock()
	defer r.managedProviderMu.Unlock()
	h, ok := r.managedProviders[id]
	if !ok {
		return h, ErrManagedProviderMissing02910
	}
	if h.ActiveRevision != expected {
		return h, ErrManagedProviderConflict02910
	}
	if target < 0 || target > int64(len(h.Revisions)) {
		return h, ErrManagedProviderMissing02910
	}
	h.ActiveRevision = target
	r.managedProviders[id] = h
	return h, nil
}
func ValidateManagedProviderDraft02910(v ManagedProviderRevision02910) error {
	if len(v.ID) < 2 || len(v.ID) > 64 || v.ID == "local" || strings.Trim(v.ID, "abcdefghijklmnopqrstuvwxyz0123456789-_.") != "" {
		return fmt.Errorf("invalid provider id")
	}
	switch v.Kind {
	case "sql", "http", "oidc", "microsoft":
	default:
		return errors.New("invalid provider kind")
	}
	if len(v.Config) == 0 || len(v.Config) > 32768 || !json.Valid(v.Config) {
		return errors.New("invalid configuration")
	}
	if len(v.Reason) < 3 || len(v.Reason) > 500 || strings.ContainsAny(v.Reason, "\r\n\x00") {
		return errors.New("invalid reason")
	}
	return nil
}

// ActiveManagedProviderReader02910 avoids materializing unbounded revision
// history during each authentication request. Full history is for Admin only.
type ActiveManagedProviderReader02910 interface {
	ListActiveManagedProviders02910(context.Context) ([]ManagedProviderRevision02910, error)
}

func (r *SQLRepository) ListActiveManagedProviders02910(ctx context.Context) ([]ManagedProviderRevision02910, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT h.provider_id,v.revision,v.kind,v.config,v.actor,v.reason,v.created_at
 FROM auth_provider_heads_02910 h JOIN auth_provider_revisions_02910 v ON v.provider_id=h.provider_id AND v.revision=h.active_revision ORDER BY h.provider_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ManagedProviderRevision02910
	for rows.Next() {
		var v ManagedProviderRevision02910
		if err := rows.Scan(&v.ID, &v.Revision, &v.Kind, &v.Config, &v.Actor, &v.Reason, &v.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func (r *MemoryRepository) ListActiveManagedProviders02910(_ context.Context) ([]ManagedProviderRevision02910, error) {
	r.managedProviderMu.Lock()
	defer r.managedProviderMu.Unlock()
	var out []ManagedProviderRevision02910
	for _, h := range r.managedProviders {
		if h.ActiveRevision > 0 && h.ActiveRevision <= int64(len(h.Revisions)) {
			out = append(out, h.Revisions[h.ActiveRevision-1])
		}
	}
	return out, nil
}

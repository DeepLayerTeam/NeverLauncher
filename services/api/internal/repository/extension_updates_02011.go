package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type extensionUpdateLease02011 struct {
	Owner     string
	ExpiresAt time.Time
}

func normalizeUpdateScope02011(scope, scopeID string) (string, string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "project" {
		return "", "", errors.New("scope must be global or project")
	}
	if scope == "global" {
		scopeID = ""
	} else if scopeID == "" {
		return "", "", errors.New("project scope requires scopeId")
	}
	return scope, scopeID, nil
}
func updateLeaseKey02011(scope, scopeID string) string { return scope + "\x00" + scopeID }

func (r *MemoryRepository) ListExtensionUpdatePins(ctx context.Context, scope, scopeID string) ([]model.ExtensionUpdatePin, error) {
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return nil, err
	}
	_ = ctx
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionUpdatePin{}
	for _, p := range r.extensionUpdatePins {
		if p.Scope == scope && p.ScopeID == scopeID {
			out = append(out, p)
		}
	}
	return out, nil
}
func (r *MemoryRepository) SetExtensionUpdatePin(ctx context.Context, p model.ExtensionUpdatePin) (model.ExtensionUpdatePin, error) {
	var err error
	p.Scope, p.ScopeID, err = normalizeUpdateScope02011(p.Scope, p.ScopeID)
	if err != nil {
		return model.ExtensionUpdatePin{}, err
	}
	_ = ctx
	p.ExtensionID = strings.ToLower(strings.TrimSpace(p.ExtensionID))
	p.Version = strings.TrimSpace(p.Version)
	if !extensionID0201.MatchString(p.ExtensionID) || !extensionSemver0201.MatchString(p.Version) {
		return model.ExtensionUpdatePin{}, errors.New("invalid extension update pin")
	}
	if _, err := r.GetExtensionRegistryVersion(context.Background(), p.ExtensionID, p.Version); err != nil {
		return model.ExtensionUpdatePin{}, fmt.Errorf("pin target must be a published registry version: %w", err)
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionUpdatePins {
		if r.extensionUpdatePins[i].ExtensionID == p.ExtensionID && r.extensionUpdatePins[i].Scope == p.Scope && r.extensionUpdatePins[i].ScopeID == p.ScopeID {
			p.CreatedAt = r.extensionUpdatePins[i].CreatedAt
			p.UpdatedAt = now
			r.extensionUpdatePins[i] = p
			return p, nil
		}
	}
	p.CreatedAt, p.UpdatedAt = now, now
	r.extensionUpdatePins = append(r.extensionUpdatePins, p)
	return p, nil
}
func (r *MemoryRepository) DeleteExtensionUpdatePin(ctx context.Context, id, scope, scopeID string) error {
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return err
	}
	_ = ctx
	id = strings.ToLower(strings.TrimSpace(id))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i, p := range r.extensionUpdatePins {
		if p.ExtensionID == id && p.Scope == scope && p.ScopeID == scopeID {
			r.extensionUpdatePins = append(r.extensionUpdatePins[:i], r.extensionUpdatePins[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}
func (r *MemoryRepository) AcquireExtensionUpdateLease(ctx context.Context, scope, scopeID, owner string, ttl time.Duration) (bool, error) {
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return false, err
	}
	_ = ctx
	owner = strings.TrimSpace(owner)
	if owner == "" || ttl <= 0 {
		return false, errors.New("owner and positive ttl are required")
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	if r.extensionUpdateLeases == nil {
		r.extensionUpdateLeases = map[string]extensionUpdateLease02011{}
	}
	key := updateLeaseKey02011(scope, scopeID)
	now := time.Now().UTC()
	if cur, ok := r.extensionUpdateLeases[key]; ok && cur.ExpiresAt.After(now) && cur.Owner != owner {
		return false, nil
	}
	r.extensionUpdateLeases[key] = extensionUpdateLease02011{Owner: owner, ExpiresAt: now.Add(ttl)}
	return true, nil
}
func (r *MemoryRepository) ReleaseExtensionUpdateLease(ctx context.Context, scope, scopeID, owner string) error {
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return err
	}
	_ = ctx
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	key := updateLeaseKey02011(scope, scopeID)
	if cur, ok := r.extensionUpdateLeases[key]; ok && cur.Owner == owner {
		delete(r.extensionUpdateLeases, key)
	}
	return nil
}
func (r *MemoryRepository) SaveExtensionUpdateTransaction(ctx context.Context, tx model.ExtensionUpdateTransaction) (model.ExtensionUpdateTransaction, error) {
	_ = ctx
	if strings.TrimSpace(tx.ID) == "" {
		return tx, errors.New("transaction id required")
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionUpdateTransactions {
		if r.extensionUpdateTransactions[i].ID == tx.ID {
			r.extensionUpdateTransactions[i] = tx
			return tx, nil
		}
	}
	r.extensionUpdateTransactions = append(r.extensionUpdateTransactions, tx)
	return tx, nil
}
func (r *MemoryRepository) GetExtensionUpdateTransaction(ctx context.Context, id string) (model.ExtensionUpdateTransaction, error) {
	_ = ctx
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, x := range r.extensionUpdateTransactions {
		if x.ID == id {
			return x, nil
		}
	}
	return model.ExtensionUpdateTransaction{}, ErrNotFound
}
func (r *MemoryRepository) ListExtensionUpdateTransactions(ctx context.Context, scope, scopeID, status string) ([]model.ExtensionUpdateTransaction, error) {
	_ = ctx
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionUpdateTransaction{}
	for _, x := range r.extensionUpdateTransactions {
		if x.Scope == scope && x.ScopeID == scopeID && (status == "" || x.Status == status) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

func (r *SQLRepository) ListExtensionUpdatePins(ctx context.Context, scope, scopeID string) ([]model.ExtensionUpdatePin, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT extension_id,scope,scope_id,version,created_at,updated_at FROM extension_update_pins WHERE scope=$1 AND scope_id=$2 ORDER BY extension_id`, scope, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ExtensionUpdatePin
	for rows.Next() {
		var p model.ExtensionUpdatePin
		if err := rows.Scan(&p.ExtensionID, &p.Scope, &p.ScopeID, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (r *SQLRepository) SetExtensionUpdatePin(ctx context.Context, p model.ExtensionUpdatePin) (model.ExtensionUpdatePin, error) {
	if err := r.check(); err != nil {
		return p, err
	}
	var err error
	p.Scope, p.ScopeID, err = normalizeUpdateScope02011(p.Scope, p.ScopeID)
	if err != nil {
		return p, err
	}
	p.ExtensionID = strings.ToLower(strings.TrimSpace(p.ExtensionID))
	p.Version = strings.TrimSpace(p.Version)
	if !extensionID0201.MatchString(p.ExtensionID) || !extensionSemver0201.MatchString(p.Version) {
		return p, errors.New("invalid extension update pin")
	}
	err = r.db.QueryRowContext(ctx, `INSERT INTO extension_update_pins(extension_id,scope,scope_id,version) SELECT $1,$2,$3,$4 WHERE EXISTS(SELECT 1 FROM extension_registry_versions WHERE extension_id=$1 AND version=$4 AND yanked_at IS NULL) ON CONFLICT(extension_id,scope,scope_id) DO UPDATE SET version=EXCLUDED.version,updated_at=now() RETURNING created_at,updated_at`, p.ExtensionID, p.Scope, p.ScopeID, p.Version).Scan(&p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, fmt.Errorf("%w: pin target registry version unavailable", ErrNotFound)
	}
	return p, err
}
func (r *SQLRepository) DeleteExtensionUpdatePin(ctx context.Context, id, scope, scopeID string) error {
	if err := r.check(); err != nil {
		return err
	}
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM extension_update_pins WHERE extension_id=$1 AND scope=$2 AND scope_id=$3`, strings.ToLower(strings.TrimSpace(id)), scope, scopeID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (r *SQLRepository) AcquireExtensionUpdateLease(ctx context.Context, scope, scopeID, owner string, ttl time.Duration) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return false, err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || ttl <= 0 {
		return false, errors.New("owner and positive ttl required")
	}
	var got bool
	err = r.db.QueryRowContext(ctx, `INSERT INTO extension_update_leases(scope,scope_id,owner,expires_at) VALUES($1,$2,$3,now()+$4::interval) ON CONFLICT(scope,scope_id) DO UPDATE SET owner=EXCLUDED.owner,expires_at=EXCLUDED.expires_at WHERE extension_update_leases.expires_at<=now() OR extension_update_leases.owner=EXCLUDED.owner RETURNING true`, scope, scopeID, owner, fmt.Sprintf("%f seconds", ttl.Seconds())).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return got, err
}
func (r *SQLRepository) ReleaseExtensionUpdateLease(ctx context.Context, scope, scopeID, owner string) error {
	if err := r.check(); err != nil {
		return err
	}
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `DELETE FROM extension_update_leases WHERE scope=$1 AND scope_id=$2 AND owner=$3`, scope, scopeID, owner)
	return err
}
func (r *SQLRepository) SaveExtensionUpdateTransaction(ctx context.Context, tx model.ExtensionUpdateTransaction) (model.ExtensionUpdateTransaction, error) {
	if err := r.check(); err != nil {
		return tx, err
	}
	plan, err := json.Marshal(tx.Plan)
	if err != nil {
		return tx, err
	}
	applied, _ := json.Marshal(tx.Applied)
	rolled, _ := json.Marshal(tx.RolledBack)
	var finished any
	if tx.FinishedAt != nil {
		finished = *tx.FinishedAt
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO extension_update_transactions(id,scope,scope_id,status,plan,applied,in_flight,rolled_back,failure,lease_owner,started_at,finished_at) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8::jsonb,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,plan=EXCLUDED.plan,applied=EXCLUDED.applied,in_flight=EXCLUDED.in_flight,rolled_back=EXCLUDED.rolled_back,failure=EXCLUDED.failure,lease_owner=EXCLUDED.lease_owner,finished_at=EXCLUDED.finished_at`, tx.ID, tx.Scope, tx.ScopeID, tx.Status, string(plan), string(applied), tx.InFlight, string(rolled), tx.Failure, tx.LeaseOwner, tx.StartedAt, finished)
	return tx, err
}
func (r *SQLRepository) GetExtensionUpdateTransaction(ctx context.Context, id string) (model.ExtensionUpdateTransaction, error) {
	if err := r.check(); err != nil {
		return model.ExtensionUpdateTransaction{}, err
	}
	var tx model.ExtensionUpdateTransaction
	var plan, applied, rolled []byte
	var finished sql.NullTime
	err := r.db.QueryRowContext(ctx, `SELECT id,scope,scope_id,status,plan,applied,in_flight,rolled_back,failure,lease_owner,started_at,finished_at FROM extension_update_transactions WHERE id=$1`, id).Scan(&tx.ID, &tx.Scope, &tx.ScopeID, &tx.Status, &plan, &applied, &tx.InFlight, &rolled, &tx.Failure, &tx.LeaseOwner, &tx.StartedAt, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return tx, ErrNotFound
	}
	if err != nil {
		return tx, err
	}
	if err = json.Unmarshal(plan, &tx.Plan); err != nil {
		return tx, err
	}
	_ = json.Unmarshal(applied, &tx.Applied)
	_ = json.Unmarshal(rolled, &tx.RolledBack)
	if finished.Valid {
		tx.FinishedAt = &finished.Time
	}
	return tx, nil
}

func (r *SQLRepository) ListExtensionUpdateTransactions(ctx context.Context, scope, scopeID, status string) ([]model.ExtensionUpdateTransaction, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	scope, scopeID, err := normalizeUpdateScope02011(scope, scopeID)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	query := `SELECT id,scope,scope_id,status,plan,applied,in_flight,rolled_back,failure,lease_owner,started_at,finished_at FROM extension_update_transactions WHERE scope=$1 AND scope_id=$2`
	args := []any{scope, scopeID}
	if status != "" {
		query += ` AND status=$3`
		args = append(args, status)
	}
	query += ` ORDER BY started_at ASC,id ASC`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionUpdateTransaction{}
	for rows.Next() {
		var tx model.ExtensionUpdateTransaction
		var plan, applied, rolled []byte
		var finished sql.NullTime
		if err := rows.Scan(&tx.ID, &tx.Scope, &tx.ScopeID, &tx.Status, &plan, &applied, &tx.InFlight, &rolled, &tx.Failure, &tx.LeaseOwner, &tx.StartedAt, &finished); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(plan, &tx.Plan); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(applied, &tx.Applied); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(rolled, &tx.RolledBack); err != nil {
			return nil, err
		}
		if finished.Valid {
			tx.FinishedAt = &finished.Time
		}
		out = append(out, tx)
	}
	return out, rows.Err()
}

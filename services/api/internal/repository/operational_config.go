package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// OperationalConfig contains only hot-reloadable, non-secret API presentation limits.
// Credentials, signer keys, network listeners and infrastructure settings stay deployment-managed.
type OperationalConfig struct {
	AuditDefaultPageSize     int  `json:"auditDefaultPageSize"`
	AuditMaxPageSize         int  `json:"auditMaxPageSize"`
	AuditLookbackDays        int  `json:"auditLookbackDays"`
	AuditExposeClientDetails bool `json:"auditExposeClientDetails"`
	JobsDefaultPageSize      int  `json:"jobsDefaultPageSize"`
	JobsMaxPageSize          int  `json:"jobsMaxPageSize"`
}
type OperationalConfigRevision struct {
	Revision     int64             `json:"revision"`
	Settings     OperationalConfig `json:"settings"`
	Actor        string            `json:"actor"`
	Reason       string            `json:"reason"`
	RestoredFrom *int64            `json:"restoredFrom,omitempty"`
	CreatedAt    time.Time         `json:"createdAt"`
}
type OperationalConfigStore interface {
	GetOperationalConfig(context.Context) (OperationalConfigRevision, error)
	ListOperationalConfigRevisions(context.Context, int) ([]OperationalConfigRevision, error)
	SaveOperationalConfig(context.Context, int64, OperationalConfig, string, string, *int64) (OperationalConfigRevision, error)
}

func DefaultOperationalConfig() OperationalConfig {
	return OperationalConfig{AuditDefaultPageSize: 25, AuditMaxPageSize: 100, AuditLookbackDays: 30, AuditExposeClientDetails: false, JobsDefaultPageSize: 25, JobsMaxPageSize: 100}
}
func (v OperationalConfig) Validate() error {
	if v.AuditDefaultPageSize < 5 || v.AuditDefaultPageSize > 100 {
		return errors.New("auditDefaultPageSize: требуется число от 5 до 100")
	}
	if v.AuditMaxPageSize < v.AuditDefaultPageSize || v.AuditMaxPageSize > 200 {
		return errors.New("auditMaxPageSize: должен быть не меньше размера страницы и не больше 200")
	}
	if v.AuditLookbackDays < 1 || v.AuditLookbackDays > 3650 {
		return errors.New("auditLookbackDays: требуется число от 1 до 3650")
	}
	if v.JobsDefaultPageSize < 5 || v.JobsDefaultPageSize > 100 {
		return errors.New("jobsDefaultPageSize: требуется число от 5 до 100")
	}
	if v.JobsMaxPageSize < v.JobsDefaultPageSize || v.JobsMaxPageSize > 200 {
		return errors.New("jobsMaxPageSize: должен быть не меньше размера страницы и не больше 200")
	}
	return nil
}

// The memory implementation is used only in development/test. Production shares revisions via SQL.
func (r *MemoryRepository) GetOperationalConfig(_ context.Context) (OperationalConfigRevision, error) {
	r.operationalConfigMu.Lock()
	defer r.operationalConfigMu.Unlock()
	if len(r.operationalConfigRevisions) == 0 {
		return OperationalConfigRevision{Revision: 1, Settings: DefaultOperationalConfig(), Actor: "system", Reason: "initial defaults"}, nil
	}
	return r.operationalConfigRevisions[len(r.operationalConfigRevisions)-1], nil
}
func (r *MemoryRepository) ListOperationalConfigRevisions(_ context.Context, limit int) ([]OperationalConfigRevision, error) {
	r.operationalConfigMu.Lock()
	defer r.operationalConfigMu.Unlock()
	if limit < 1 || limit > 100 {
		limit = 50
	}
	all := r.operationalConfigRevisions
	if len(all) == 0 {
		all = []OperationalConfigRevision{{Revision: 1, Settings: DefaultOperationalConfig(), Actor: "system", Reason: "initial defaults"}}
	}
	out := make([]OperationalConfigRevision, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
func (r *MemoryRepository) SaveOperationalConfig(_ context.Context, expected int64, settings OperationalConfig, actor, reason string, restore *int64) (OperationalConfigRevision, error) {
	if restore == nil {
		if err := settings.Validate(); err != nil {
			return OperationalConfigRevision{}, err
		}
	}
	r.operationalConfigMu.Lock()
	defer r.operationalConfigMu.Unlock()
	if len(r.operationalConfigRevisions) == 0 {
		r.operationalConfigRevisions = []OperationalConfigRevision{{Revision: 1, Settings: DefaultOperationalConfig(), Actor: "system", Reason: "initial defaults"}}
	}
	prev := r.operationalConfigRevisions[len(r.operationalConfigRevisions)-1]
	if prev.Revision != expected {
		return OperationalConfigRevision{}, ErrConflict
	}
	if restore != nil {
		found := false
		for _, revision := range r.operationalConfigRevisions {
			if revision.Revision == *restore {
				settings = revision.Settings
				found = true
				break
			}
		}
		if !found {
			return OperationalConfigRevision{}, ErrNotFound
		}
	}
	v := OperationalConfigRevision{Revision: expected + 1, Settings: settings, Actor: actor, Reason: reason, RestoredFrom: restore, CreatedAt: time.Now().UTC()}
	r.operationalConfigRevisions = append(r.operationalConfigRevisions, v)
	return v, nil
}

func scanOperationalConfig(row interface{ Scan(...any) error }) (OperationalConfigRevision, error) {
	var v OperationalConfigRevision
	var raw []byte
	var restored sql.NullInt64
	err := row.Scan(&v.Revision, &raw, &v.Actor, &v.Reason, &restored, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if restored.Valid {
		v.RestoredFrom = &restored.Int64
	}
	err = json.Unmarshal(raw, &v.Settings)
	return v, err
}
func (r *SQLRepository) GetOperationalConfig(ctx context.Context) (OperationalConfigRevision, error) {
	if err := r.check(); err != nil {
		return OperationalConfigRevision{}, err
	}
	return scanOperationalConfig(r.db.QueryRowContext(ctx, `SELECT revision,settings,actor,reason,restored_from,created_at FROM operational_config_revisions ORDER BY revision DESC LIMIT 1`))
}
func (r *SQLRepository) ListOperationalConfigRevisions(ctx context.Context, limit int) ([]OperationalConfigRevision, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `SELECT revision,settings,actor,reason,restored_from,created_at FROM operational_config_revisions ORDER BY revision DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OperationalConfigRevision{}
	for rows.Next() {
		v, err := scanOperationalConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (r *SQLRepository) SaveOperationalConfig(ctx context.Context, expected int64, settings OperationalConfig, actor, reason string, restore *int64) (OperationalConfigRevision, error) {
	if err := r.check(); err != nil {
		return OperationalConfigRevision{}, err
	}
	if restore == nil {
		if err := settings.Validate(); err != nil {
			return OperationalConfigRevision{}, err
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return OperationalConfigRevision{}, err
	}
	defer tx.Rollback()
	if restore != nil {
		var raw []byte
		err = tx.QueryRowContext(ctx, `SELECT settings FROM operational_config_revisions WHERE revision=$1`, *restore).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return OperationalConfigRevision{}, ErrNotFound
		}
		if err != nil {
			return OperationalConfigRevision{}, err
		}
		if err = json.Unmarshal(raw, &settings); err != nil {
			return OperationalConfigRevision{}, err
		}
		if err = settings.Validate(); err != nil {
			return OperationalConfigRevision{}, err
		}
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return OperationalConfigRevision{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE operational_config_current SET revision=revision+1,settings=$1,updated_at=now() WHERE id=1 AND revision=$2`, raw, expected)
	if err != nil {
		return OperationalConfigRevision{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return OperationalConfigRevision{}, err
	}
	if n != 1 {
		return OperationalConfigRevision{}, ErrConflict
	}
	v := OperationalConfigRevision{Revision: expected + 1, Settings: settings, Actor: actor, Reason: reason, RestoredFrom: restore}
	err = tx.QueryRowContext(ctx, `INSERT INTO operational_config_revisions(revision,settings,actor,reason,restored_from) VALUES($1,$2,$3,$4,$5) RETURNING created_at`, v.Revision, raw, actor, reason, restore).Scan(&v.CreatedAt)
	if err != nil {
		return OperationalConfigRevision{}, fmt.Errorf("save config revision: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return OperationalConfigRevision{}, err
	}
	return v, nil
}

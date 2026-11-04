package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// OfficialProviderSettings02611 contains public-app configuration only. Store
// Microsoft client secrets, tokens, redirect URLs, or arbitrary issuer endpoints here.
type OfficialProviderSettings02611 struct {
	ClientID       string `json:"clientId"`
	Enabled        bool   `json:"enabled"`
	BrowserEnabled bool   `json:"browserEnabled"`
	DeviceEnabled  bool   `json:"deviceEnabled"`
	Issuer         string `json:"issuer"`
}
type OfficialProviderRevision02611 struct {
	Revision  int64                         `json:"revision"`
	Settings  OfficialProviderSettings02611 `json:"settings"`
	Actor     string                        `json:"actor"`
	Reason    string                        `json:"reason"`
	CreatedAt time.Time                     `json:"createdAt"`
}
type OfficialProviderStore02611 interface {
	GetOfficialProvider02611(context.Context) (OfficialProviderRevision02611, error)
	SaveOfficialProvider02611(context.Context, int64, OfficialProviderSettings02611, string, string) (OfficialProviderRevision02611, error)
	ListOfficialProviderHistory02611(context.Context, int) ([]OfficialProviderRevision02611, error)
}

var ErrOfficialProviderConflict02611 = errors.New("official provider revision conflict")
var clientIDPattern02611 = regexp.MustCompile(`(?i)^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)

func (v OfficialProviderSettings02611) Validate() error {
	if v.Issuer != "consumers" {
		return errors.New("only personal Microsoft accounts (consumers) are supported")
	}
	if v.ClientID != "" && (!clientIDPattern02611.MatchString(v.ClientID) || strings.EqualFold(v.ClientID, "00000000-0000-0000-0000-000000000000")) {
		return errors.New("clientId must be a registered public application UUID")
	}
	if v.Enabled && v.ClientID == "" {
		return errors.New("clientId is required for enabled provider")
	}
	if v.Enabled && !v.BrowserEnabled && !v.DeviceEnabled {
		return errors.New("at least one authentication flow must be enabled")
	}
	return nil
}
func DefaultOfficialProvider02611(clientID string) OfficialProviderSettings02611 {
	ok := clientIDPattern02611.MatchString(clientID) && !strings.EqualFold(clientID, "00000000-0000-0000-0000-000000000000")
	return OfficialProviderSettings02611{ClientID: clientID, Enabled: ok, BrowserEnabled: true, DeviceEnabled: true, Issuer: "consumers"}
}
func (r *MemoryRepository) GetOfficialProvider02611(_ context.Context) (OfficialProviderRevision02611, error) {
	r.officialProviderMu.Lock()
	defer r.officialProviderMu.Unlock()
	if len(r.officialProviderHistory) == 0 {
		return OfficialProviderRevision02611{}, nil
	}
	return r.officialProviderHistory[len(r.officialProviderHistory)-1], nil
}
func (r *MemoryRepository) SaveOfficialProvider02611(_ context.Context, expected int64, settings OfficialProviderSettings02611, actor, reason string) (OfficialProviderRevision02611, error) {
	if err := settings.Validate(); err != nil {
		return OfficialProviderRevision02611{}, err
	}
	r.officialProviderMu.Lock()
	defer r.officialProviderMu.Unlock()
	current := int64(len(r.officialProviderHistory))
	if expected != current {
		return OfficialProviderRevision02611{}, ErrOfficialProviderConflict02611
	}
	rev := OfficialProviderRevision02611{Revision: current + 1, Settings: settings, Actor: actor, Reason: reason, CreatedAt: time.Now().UTC()}
	r.officialProviderHistory = append(r.officialProviderHistory, rev)
	return rev, nil
}
func (r *MemoryRepository) ListOfficialProviderHistory02611(_ context.Context, limit int) ([]OfficialProviderRevision02611, error) {
	r.officialProviderMu.Lock()
	defer r.officialProviderMu.Unlock()
	if limit < 1 || limit > 100 {
		limit = 50
	}
	result := make([]OfficialProviderRevision02611, 0, limit)
	for i := len(r.officialProviderHistory) - 1; i >= 0 && len(result) < limit; i-- {
		result = append(result, r.officialProviderHistory[i])
	}
	return result, nil
}
func scanOfficialProvider02611(s interface{ Scan(...any) error }) (OfficialProviderRevision02611, error) {
	var v OfficialProviderRevision02611
	err := s.Scan(&v.Revision, &v.Settings.ClientID, &v.Settings.Enabled, &v.Settings.BrowserEnabled, &v.Settings.DeviceEnabled, &v.Settings.Issuer, &v.Actor, &v.Reason, &v.CreatedAt)
	return v, err
}

const officialProviderColumns02611 = `revision,client_id,enabled,browser_enabled,device_enabled,issuer,actor,reason,created_at`

func (r *SQLRepository) GetOfficialProvider02611(ctx context.Context) (OfficialProviderRevision02611, error) {
	if err := r.check(); err != nil {
		return OfficialProviderRevision02611{}, err
	}
	v, err := scanOfficialProvider02611(r.db.QueryRowContext(ctx, `SELECT `+officialProviderColumns02611+` FROM official_provider_config_02611 WHERE singleton=true`))
	if errors.Is(err, sql.ErrNoRows) {
		return OfficialProviderRevision02611{}, nil
	}
	return v, err
}
func (r *SQLRepository) SaveOfficialProvider02611(ctx context.Context, expected int64, settings OfficialProviderSettings02611, actor, reason string) (OfficialProviderRevision02611, error) {
	if err := settings.Validate(); err != nil {
		return OfficialProviderRevision02611{}, err
	}
	if err := r.check(); err != nil {
		return OfficialProviderRevision02611{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return OfficialProviderRevision02611{}, err
	}
	defer tx.Rollback()
	var v OfficialProviderRevision02611
	// CAS UPDATE/INSERT works across independent API replicas; transaction includes the immutable history row.
	if expected == 0 {
		v, err = scanOfficialProvider02611(tx.QueryRowContext(ctx, `INSERT INTO official_provider_config_02611(singleton,revision,client_id,enabled,browser_enabled,device_enabled,issuer,actor,reason) VALUES(true,1,$1,$2,$3,$4,$5,$6,$7) ON CONFLICT(singleton) DO NOTHING RETURNING `+officialProviderColumns02611, settings.ClientID, settings.Enabled, settings.BrowserEnabled, settings.DeviceEnabled, settings.Issuer, actor, reason))
	} else {
		v, err = scanOfficialProvider02611(tx.QueryRowContext(ctx, `UPDATE official_provider_config_02611 SET revision=revision+1,client_id=$1,enabled=$2,browser_enabled=$3,device_enabled=$4,issuer=$5,actor=$6,reason=$7,created_at=now() WHERE singleton=true AND revision=$8 RETURNING `+officialProviderColumns02611, settings.ClientID, settings.Enabled, settings.BrowserEnabled, settings.DeviceEnabled, settings.Issuer, actor, reason, expected))
	}
	if errors.Is(err, sql.ErrNoRows) {
		return OfficialProviderRevision02611{}, ErrOfficialProviderConflict02611
	}
	if err != nil {
		return OfficialProviderRevision02611{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO official_provider_history_02611(revision,client_id,enabled,browser_enabled,device_enabled,issuer,actor,reason,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, v.Revision, v.Settings.ClientID, v.Settings.Enabled, v.Settings.BrowserEnabled, v.Settings.DeviceEnabled, v.Settings.Issuer, v.Actor, v.Reason, v.CreatedAt)
	if err != nil {
		return OfficialProviderRevision02611{}, fmt.Errorf("provider audit persistence: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return OfficialProviderRevision02611{}, err
	}
	return v, nil
}
func (r *SQLRepository) ListOfficialProviderHistory02611(ctx context.Context, limit int) ([]OfficialProviderRevision02611, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+officialProviderColumns02611+` FROM official_provider_history_02611 ORDER BY revision DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]OfficialProviderRevision02611, 0)
	for rows.Next() {
		v, e := scanOfficialProvider02611(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

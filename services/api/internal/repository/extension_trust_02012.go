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

func normalizeTrustPolicy02012(p model.ExtensionTrustPolicy) (model.ExtensionTrustPolicy, error) {
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode == "" {
		p.Mode = model.ExtensionTrustModeStrict
	}
	if p.Mode != model.ExtensionTrustModeStrict && p.Mode != model.ExtensionTrustModeAudit {
		return model.ExtensionTrustPolicy{}, errors.New("расширение доверие политика режим должен быть строгий или аудит")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(p.AllowedPublishers))
	for _, raw := range p.AllowedPublishers {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if !registryPublisherID0203.MatchString(id) {
			return model.ExtensionTrustPolicy{}, fmt.Errorf("недопустимый разрешён издатель ID %q", id)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	p.AllowedPublishers = out
	return p, nil
}

func normalizeEmergencyScope02012(scope, scopeID string) (string, string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	if scope == "" {
		scope = "global"
	}
	if scope == "global" {
		return scope, "", nil
	}
	if scope == "project" && scopeID != "" {
		return scope, scopeID, nil
	}
	return "", "", errors.New("область должен быть глобальный или проект с scopeId")
}

func (r *MemoryRepository) GetExtensionTrustPolicy(ctx context.Context) (model.ExtensionTrustPolicy, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionTrustPolicy{}, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	p := r.extensionTrustPolicy
	p.AllowedPublishers = append([]string(nil), p.AllowedPublishers...)
	return p, nil
}
func (r *MemoryRepository) SaveExtensionTrustPolicy(ctx context.Context, p model.ExtensionTrustPolicy) (model.ExtensionTrustPolicy, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionTrustPolicy{}, err
	}
	p, err := normalizeTrustPolicy02012(p)
	if err != nil {
		return model.ExtensionTrustPolicy{}, err
	}
	p.UpdatedAt = time.Now().UTC()
	r.extensionMu.Lock()
	r.extensionTrustPolicy = p
	r.extensionMu.Unlock()
	return p, nil
}
func (r *MemoryRepository) RevokeExtensionRegistryPublisherKey(ctx context.Context, publisherID, fingerprint string) (model.ExtensionRegistryPublisherKey, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	publisherID = strings.ToLower(strings.TrimSpace(publisherID))
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionRegistryKeys {
		k := &r.extensionRegistryKeys[i]
		if k.PublisherID == publisherID && k.Fingerprint == fingerprint {
			if k.RevokedAt == nil {
				now := time.Now().UTC()
				k.RevokedAt = &now
			}
			k.Active = false
			return *k, nil
		}
	}
	return model.ExtensionRegistryPublisherKey{}, ErrNotFound
}
func normalizeQuarantine02012(e model.ExtensionQuarantineEntry) (model.ExtensionQuarantineEntry, error) {
	e.ID = strings.TrimSpace(e.ID)
	e.PackageIdentity = strings.ToLower(strings.TrimSpace(e.PackageIdentity))
	e.ArtifactSHA256 = strings.ToLower(strings.TrimSpace(e.ArtifactSHA256))
	e.Reason = strings.TrimSpace(e.Reason)
	if e.ID == "" || len(e.ID) > 200 {
		return e, errors.New("карантин ID является обязательный")
	}
	if !registryIdentity0203.MatchString(e.PackageIdentity) || !registrySHA0203.MatchString(e.ArtifactSHA256) {
		return e, errors.New("карантин пакет идентичность/SHA-256 является недопустимый")
	}
	if e.Reason == "" || len(e.Reason) > 1000 {
		return e, errors.New("карантин reason является обязательный и ограничение к 1000 chars")
	}
	e.ExtensionID = strings.ToLower(strings.TrimSpace(e.ExtensionID))
	e.PublisherID = strings.ToLower(strings.TrimSpace(e.PublisherID))
	e.KeyFingerprint = strings.ToLower(strings.TrimSpace(e.KeyFingerprint))
	return e, nil
}
func (r *MemoryRepository) SaveExtensionQuarantine(ctx context.Context, e model.ExtensionQuarantineEntry) (model.ExtensionQuarantineEntry, error) {
	if err := ctx.Err(); err != nil {
		return e, err
	}
	e, err := normalizeQuarantine02012(e)
	if err != nil {
		return e, err
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	e.Active = true
	e.ReleasedAt = nil
	e.ReleasedBy = ""
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, cur := range r.extensionQuarantine {
		if cur.ID == e.ID {
			return model.ExtensionQuarantineEntry{}, fmt.Errorf("%w: карантин ID уже существует", ErrConflict)
		}
	}
	r.extensionQuarantine = append(r.extensionQuarantine, e)
	return e, nil
}
func (r *MemoryRepository) ListExtensionQuarantine(ctx context.Context, activeOnly bool) ([]model.ExtensionQuarantineEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionQuarantineEntry, 0)
	for _, e := range r.extensionQuarantine {
		if !activeOnly || e.Active {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (r *MemoryRepository) GetExtensionQuarantine(ctx context.Context, id string) (model.ExtensionQuarantineEntry, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionQuarantineEntry{}, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, e := range r.extensionQuarantine {
		if e.ID == strings.TrimSpace(id) {
			return e, nil
		}
	}
	return model.ExtensionQuarantineEntry{}, ErrNotFound
}
func (r *MemoryRepository) ReleaseExtensionQuarantine(ctx context.Context, id, actor string) (model.ExtensionQuarantineEntry, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionQuarantineEntry{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionQuarantine {
		e := &r.extensionQuarantine[i]
		if e.ID == strings.TrimSpace(id) {
			if e.Active {
				now := time.Now().UTC()
				e.Active = false
				e.ReleasedAt = &now
				e.ReleasedBy = actor
			}
			return *e, nil
		}
	}
	return model.ExtensionQuarantineEntry{}, ErrNotFound
}
func (r *MemoryRepository) IsExtensionPackageQuarantined(ctx context.Context, identity string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	identity = strings.ToLower(strings.TrimSpace(identity))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, e := range r.extensionQuarantine {
		if e.Active && e.PackageIdentity == identity {
			return true, nil
		}
	}
	return false, nil
}
func normalizeEmergency02012(e model.ExtensionEmergencyDisable) (model.ExtensionEmergencyDisable, error) {
	var err error
	e.Scope, e.ScopeID, err = normalizeEmergencyScope02012(e.Scope, e.ScopeID)
	if err != nil {
		return e, err
	}
	e.ExtensionID = strings.ToLower(strings.TrimSpace(e.ExtensionID))
	e.Reason = strings.TrimSpace(e.Reason)
	e.Source = strings.TrimSpace(e.Source)
	if !extensionID0201.MatchString(e.ExtensionID) {
		return e, errors.New("недопустимый расширение ID")
	}
	if e.Reason == "" || len(e.Reason) > 1000 {
		return e, errors.New("аварийный отключить reason является обязательный")
	}
	if e.Source == "" {
		e.Source = "admin"
	}
	return e, nil
}
func (r *MemoryRepository) SetExtensionEmergencyDisable(ctx context.Context, e model.ExtensionEmergencyDisable) (model.ExtensionEmergencyDisable, error) {
	if err := ctx.Err(); err != nil {
		return e, err
	}
	e, err := normalizeEmergency02012(e)
	if err != nil {
		return e, err
	}
	now := time.Now().UTC()
	e.CreatedAt = now
	e.ClearedAt = nil
	e.ClearedBy = ""
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionEmergencyDisables {
		cur := &r.extensionEmergencyDisables[i]
		if cur.ExtensionID == e.ExtensionID && cur.Scope == e.Scope && cur.ScopeID == e.ScopeID {
			*cur = e
			return e, nil
		}
	}
	r.extensionEmergencyDisables = append(r.extensionEmergencyDisables, e)
	return e, nil
}
func (r *MemoryRepository) GetExtensionEmergencyDisable(ctx context.Context, id, scope, scopeID string) (model.ExtensionEmergencyDisable, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	scope, scopeID, err := normalizeEmergencyScope02012(scope, scopeID)
	if err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	id = strings.ToLower(strings.TrimSpace(id))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, e := range r.extensionEmergencyDisables {
		if e.ExtensionID == id && e.Scope == scope && e.ScopeID == scopeID && e.ClearedAt == nil {
			return e, nil
		}
	}
	return model.ExtensionEmergencyDisable{}, ErrNotFound
}
func (r *MemoryRepository) ListExtensionEmergencyDisables(ctx context.Context, activeOnly bool) ([]model.ExtensionEmergencyDisable, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionEmergencyDisable, 0)
	for _, e := range r.extensionEmergencyDisables {
		if !activeOnly || e.ClearedAt == nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (r *MemoryRepository) ClearExtensionEmergencyDisable(ctx context.Context, id, scope, scopeID, actor string) (model.ExtensionEmergencyDisable, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	scope, scopeID, err := normalizeEmergencyScope02012(scope, scopeID)
	if err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	id = strings.ToLower(strings.TrimSpace(id))
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionEmergencyDisables {
		e := &r.extensionEmergencyDisables[i]
		if e.ExtensionID == id && e.Scope == scope && e.ScopeID == scopeID {
			if e.ClearedAt == nil {
				now := time.Now().UTC()
				e.ClearedAt = &now
				e.ClearedBy = actor
			}
			return *e, nil
		}
	}
	return model.ExtensionEmergencyDisable{}, ErrNotFound
}

func (r *SQLRepository) GetExtensionTrustPolicy(ctx context.Context) (model.ExtensionTrustPolicy, error) {
	if err := r.check(); err != nil {
		return model.ExtensionTrustPolicy{}, err
	}
	var p model.ExtensionTrustPolicy
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT mode,allowed_publishers,updated_at FROM extension_trust_policy WHERE singleton=TRUE`).Scan(&p.Mode, &raw, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionTrustPolicy{Mode: model.ExtensionTrustModeStrict, AllowedPublishers: []string{}}, nil
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p.AllowedPublishers)
	return p, err
}
func (r *SQLRepository) SaveExtensionTrustPolicy(ctx context.Context, p model.ExtensionTrustPolicy) (model.ExtensionTrustPolicy, error) {
	if err := r.check(); err != nil {
		return p, err
	}
	p, err := normalizeTrustPolicy02012(p)
	if err != nil {
		return p, err
	}
	raw, _ := json.Marshal(p.AllowedPublishers)
	err = r.db.QueryRowContext(ctx, `INSERT INTO extension_trust_policy(singleton,mode,allowed_publishers) VALUES(TRUE,$1,$2::jsonb) ON CONFLICT(singleton) DO UPDATE SET mode=EXCLUDED.mode,allowed_publishers=EXCLUDED.allowed_publishers,updated_at=now() RETURNING updated_at`, p.Mode, string(raw)).Scan(&p.UpdatedAt)
	return p, err
}
func (r *SQLRepository) RevokeExtensionRegistryPublisherKey(ctx context.Context, publisherID, fingerprint string) (model.ExtensionRegistryPublisherKey, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	publisherID = strings.ToLower(strings.TrimSpace(publisherID))
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	res, err := r.db.ExecContext(ctx, `UPDATE extension_registry_publisher_keys SET active=FALSE,revoked_at=COALESCE(revoked_at,now()) WHERE publisher_id=$1 AND fingerprint=$2`, publisherID, fingerprint)
	if err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.ExtensionRegistryPublisherKey{}, ErrNotFound
	}
	return scanRegistryPublisherKey0203(r.db.QueryRowContext(ctx, `SELECT publisher_id,fingerprint,algorithm,public_key_base64,active,created_at,revoked_at FROM extension_registry_publisher_keys WHERE publisher_id=$1 AND fingerprint=$2`, publisherID, fingerprint))
}
func scanQuarantine02012(s interface{ Scan(...any) error }) (model.ExtensionQuarantineEntry, error) {
	var e model.ExtensionQuarantineEntry
	var released sql.NullTime
	err := s.Scan(&e.ID, &e.PackageIdentity, &e.ArtifactSHA256, &e.ExtensionID, &e.Version, &e.PublisherID, &e.KeyFingerprint, &e.Reason, &e.StorageProject, &e.StorageVersion, &e.StoragePath, &e.Active, &e.CreatedAt, &released, &e.ReleasedBy)
	if released.Valid {
		e.ReleasedAt = &released.Time
	}
	return e, err
}

const quarantineSelect02012 = `SELECT id,package_identity,artifact_sha256,extension_id,version,publisher_id,key_fingerprint,reason,storage_project,storage_version,storage_path,active,created_at,released_at,released_by FROM extension_quarantine`

func (r *SQLRepository) SaveExtensionQuarantine(ctx context.Context, e model.ExtensionQuarantineEntry) (model.ExtensionQuarantineEntry, error) {
	if err := r.check(); err != nil {
		return e, err
	}
	e, err := normalizeQuarantine02012(e)
	if err != nil {
		return e, err
	}
	return scanQuarantine02012(r.db.QueryRowContext(ctx, `INSERT INTO extension_quarantine(id,package_identity,artifact_sha256,extension_id,version,publisher_id,key_fingerprint,reason,storage_project,storage_version,storage_path,active) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,TRUE) RETURNING id,package_identity,artifact_sha256,extension_id,version,publisher_id,key_fingerprint,reason,storage_project,storage_version,storage_path,active,created_at,released_at,released_by`, e.ID, e.PackageIdentity, e.ArtifactSHA256, e.ExtensionID, e.Version, e.PublisherID, e.KeyFingerprint, e.Reason, e.StorageProject, e.StorageVersion, e.StoragePath))
}
func (r *SQLRepository) ListExtensionQuarantine(ctx context.Context, activeOnly bool) ([]model.ExtensionQuarantineEntry, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	q := quarantineSelect02012
	if activeOnly {
		q += ` WHERE active=TRUE`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionQuarantineEntry{}
	for rows.Next() {
		e, err := scanQuarantine02012(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (r *SQLRepository) GetExtensionQuarantine(ctx context.Context, id string) (model.ExtensionQuarantineEntry, error) {
	if err := r.check(); err != nil {
		return model.ExtensionQuarantineEntry{}, err
	}
	e, err := scanQuarantine02012(r.db.QueryRowContext(ctx, quarantineSelect02012+` WHERE id=$1`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}
func (r *SQLRepository) ReleaseExtensionQuarantine(ctx context.Context, id, actor string) (model.ExtensionQuarantineEntry, error) {
	if err := r.check(); err != nil {
		return model.ExtensionQuarantineEntry{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	e, err := scanQuarantine02012(r.db.QueryRowContext(ctx, `UPDATE extension_quarantine SET active=FALSE,released_at=COALESCE(released_at,now()),released_by=CASE WHEN released_by='' THEN $2 ELSE released_by END WHERE id=$1 RETURNING id,package_identity,artifact_sha256,extension_id,version,publisher_id,key_fingerprint,reason,storage_project,storage_version,storage_path,active,created_at,released_at,released_by`, strings.TrimSpace(id), actor))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}
func (r *SQLRepository) IsExtensionPackageQuarantined(ctx context.Context, identity string) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM extension_quarantine WHERE package_identity=$1 AND active=TRUE)`, strings.ToLower(strings.TrimSpace(identity))).Scan(&ok)
	return ok, err
}
func scanEmergency02012(s interface{ Scan(...any) error }) (model.ExtensionEmergencyDisable, error) {
	var e model.ExtensionEmergencyDisable
	var cleared sql.NullTime
	err := s.Scan(&e.ExtensionID, &e.Scope, &e.ScopeID, &e.Reason, &e.Source, &e.CreatedAt, &cleared, &e.ClearedBy)
	if cleared.Valid {
		e.ClearedAt = &cleared.Time
	}
	return e, err
}

const emergencySelect02012 = `SELECT extension_id,scope,scope_id,reason,source,created_at,cleared_at,cleared_by FROM extension_emergency_disables`

func (r *SQLRepository) SetExtensionEmergencyDisable(ctx context.Context, e model.ExtensionEmergencyDisable) (model.ExtensionEmergencyDisable, error) {
	if err := r.check(); err != nil {
		return e, err
	}
	e, err := normalizeEmergency02012(e)
	if err != nil {
		return e, err
	}
	return scanEmergency02012(r.db.QueryRowContext(ctx, `INSERT INTO extension_emergency_disables(extension_id,scope,scope_id,reason,source) VALUES($1,$2,$3,$4,$5) ON CONFLICT(extension_id,scope,scope_id) DO UPDATE SET reason=EXCLUDED.reason,source=EXCLUDED.source,created_at=now(),cleared_at=NULL,cleared_by='' RETURNING extension_id,scope,scope_id,reason,source,created_at,cleared_at,cleared_by`, e.ExtensionID, e.Scope, e.ScopeID, e.Reason, e.Source))
}
func (r *SQLRepository) GetExtensionEmergencyDisable(ctx context.Context, id, scope, scopeID string) (model.ExtensionEmergencyDisable, error) {
	if err := r.check(); err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	scope, scopeID, err := normalizeEmergencyScope02012(scope, scopeID)
	if err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	e, err := scanEmergency02012(r.db.QueryRowContext(ctx, emergencySelect02012+` WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 AND cleared_at IS NULL`, strings.ToLower(strings.TrimSpace(id)), scope, scopeID))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}
func (r *SQLRepository) ListExtensionEmergencyDisables(ctx context.Context, activeOnly bool) ([]model.ExtensionEmergencyDisable, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	q := emergencySelect02012
	if activeOnly {
		q += ` WHERE cleared_at IS NULL`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionEmergencyDisable{}
	for rows.Next() {
		e, err := scanEmergency02012(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (r *SQLRepository) ClearExtensionEmergencyDisable(ctx context.Context, id, scope, scopeID, actor string) (model.ExtensionEmergencyDisable, error) {
	if err := r.check(); err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	scope, scopeID, err := normalizeEmergencyScope02012(scope, scopeID)
	if err != nil {
		return model.ExtensionEmergencyDisable{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	e, err := scanEmergency02012(r.db.QueryRowContext(ctx, `UPDATE extension_emergency_disables SET cleared_at=COALESCE(cleared_at,now()),cleared_by=CASE WHEN cleared_by='' THEN $4 ELSE cleared_by END WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 RETURNING extension_id,scope,scope_id,reason,source,created_at,cleared_at,cleared_by`, strings.ToLower(strings.TrimSpace(id)), scope, scopeID, actor))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

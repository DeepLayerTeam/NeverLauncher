package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var extensionSecretName0207 = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

func normalizeSecurityScope0207(scope, scopeID string) (string, string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "project" {
		return "", "", errors.New("extension security scope must be global or project")
	}
	if scope == "global" {
		scopeID = ""
	} else if scopeID == "" {
		return "", "", errors.New("project security scope requires scopeId")
	}
	return scope, scopeID, nil
}

func normalizeGrant0207(in model.ExtensionPermissionGrant) (model.ExtensionPermissionGrant, error) {
	g := in
	g.ExtensionID = strings.ToLower(strings.TrimSpace(g.ExtensionID))
	g.Permission = strings.ToLower(strings.TrimSpace(g.Permission))
	g.GrantedBy = strings.TrimSpace(g.GrantedBy)
	g.Reason = strings.TrimSpace(g.Reason)
	var err error
	g.Scope, g.ScopeID, err = normalizeSecurityScope0207(g.Scope, g.ScopeID)
	if err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	if !extensionID0201.MatchString(g.ExtensionID) {
		return model.ExtensionPermissionGrant{}, fmt.Errorf("invalid extension id %q", g.ExtensionID)
	}
	if !extensionPermission0201.MatchString(g.Permission) {
		return model.ExtensionPermissionGrant{}, fmt.Errorf("invalid extension permission %q", g.Permission)
	}
	if g.GrantedBy == "" || len(g.GrantedBy) > 255 {
		return model.ExtensionPermissionGrant{}, errors.New("grantedBy is required")
	}
	if len(g.Reason) > 1000 {
		return model.ExtensionPermissionGrant{}, errors.New("grant reason exceeds 1000 characters")
	}
	return g, nil
}

func normalizeSecret0207(in model.ExtensionSecret) (model.ExtensionSecret, error) {
	s := in
	s.ExtensionID = strings.ToLower(strings.TrimSpace(s.ExtensionID))
	s.Name = strings.TrimSpace(s.Name)
	s.KeyVersion = strings.TrimSpace(s.KeyVersion)
	s.UpdatedBy = strings.TrimSpace(s.UpdatedBy)
	var err error
	s.Scope, s.ScopeID, err = normalizeSecurityScope0207(s.Scope, s.ScopeID)
	if err != nil {
		return model.ExtensionSecret{}, err
	}
	if !extensionID0201.MatchString(s.ExtensionID) {
		return model.ExtensionSecret{}, fmt.Errorf("invalid extension id %q", s.ExtensionID)
	}
	if !extensionSecretName0207.MatchString(s.Name) {
		return model.ExtensionSecret{}, fmt.Errorf("invalid extension secret name %q", s.Name)
	}
	if len(s.Nonce) != 12 {
		return model.ExtensionSecret{}, errors.New("extension secret nonce must be 12 bytes")
	}
	if len(s.Ciphertext) < 16 || len(s.Ciphertext) > (1<<20)+16 {
		return model.ExtensionSecret{}, errors.New("extension secret ciphertext size is invalid")
	}
	if s.KeyVersion == "" || len(s.KeyVersion) > 64 {
		return model.ExtensionSecret{}, errors.New("extension secret keyVersion is required")
	}
	if s.UpdatedBy == "" || len(s.UpdatedBy) > 255 {
		return model.ExtensionSecret{}, errors.New("extension secret updatedBy is required")
	}
	return s, nil
}

func (r *MemoryRepository) ListExtensionPermissionGrants(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionPermissionGrant, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionPermissionGrant, 0)
	for _, g := range r.extensionPermissionGrants {
		if g.ExtensionID != extensionID {
			continue
		}
		if scope != "" && g.Scope != scope {
			continue
		}
		if scopeID != "" && g.ScopeID != scopeID {
			continue
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope == out[j].Scope && out[i].ScopeID == out[j].ScopeID {
			return out[i].Permission < out[j].Permission
		}
		if out[i].Scope == out[j].Scope {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Scope < out[j].Scope
	})
	return out, nil
}
func (r *MemoryRepository) GrantExtensionPermission(ctx context.Context, grant model.ExtensionPermissionGrant) (model.ExtensionPermissionGrant, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	g, err := normalizeGrant0207(grant)
	if err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	foundExt := false
	for _, e := range r.extensions {
		if e.ID == g.ExtensionID {
			foundExt = true
			break
		}
	}
	if !foundExt {
		return model.ExtensionPermissionGrant{}, ErrNotFound
	}
	now := time.Now().UTC()
	for i, existing := range r.extensionPermissionGrants {
		if existing.ExtensionID == g.ExtensionID && existing.Scope == g.Scope && existing.ScopeID == g.ScopeID && existing.Permission == g.Permission {
			g.CreatedAt = existing.CreatedAt
			g.UpdatedAt = now
			r.extensionPermissionGrants[i] = g
			return g, nil
		}
	}
	g.CreatedAt = now
	g.UpdatedAt = now
	r.extensionPermissionGrants = append(r.extensionPermissionGrants, g)
	return g, nil
}
func (r *MemoryRepository) RevokeExtensionPermission(ctx context.Context, extensionID, scope, scopeID, permission string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, scopeID, err := normalizeSecurityScope0207(scope, scopeID)
	if err != nil {
		return err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	permission = strings.ToLower(strings.TrimSpace(permission))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i, g := range r.extensionPermissionGrants {
		if g.ExtensionID == extensionID && g.Scope == scope && g.ScopeID == scopeID && g.Permission == permission {
			r.extensionPermissionGrants = append(r.extensionPermissionGrants[:i], r.extensionPermissionGrants[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}
func (r *MemoryRepository) PutExtensionSecret(ctx context.Context, secret model.ExtensionSecret) (model.ExtensionSecret, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionSecret{}, err
	}
	s, err := normalizeSecret0207(secret)
	if err != nil {
		return model.ExtensionSecret{}, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	now := time.Now().UTC()
	for i, ex := range r.extensionSecrets {
		if ex.ExtensionID == s.ExtensionID && ex.Scope == s.Scope && ex.ScopeID == s.ScopeID && ex.Name == s.Name {
			s.CreatedAt = ex.CreatedAt
			s.UpdatedAt = now
			r.extensionSecrets[i] = s
			return s, nil
		}
	}
	s.CreatedAt = now
	s.UpdatedAt = now
	r.extensionSecrets = append(r.extensionSecrets, s)
	return s, nil
}
func (r *MemoryRepository) GetExtensionSecret(ctx context.Context, extensionID, scope, scopeID, name string) (model.ExtensionSecret, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionSecret{}, err
	}
	scope, scopeID, err := normalizeSecurityScope0207(scope, scopeID)
	if err != nil {
		return model.ExtensionSecret{}, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	name = strings.TrimSpace(name)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, s := range r.extensionSecrets {
		if s.ExtensionID == extensionID && s.Scope == scope && s.ScopeID == scopeID && s.Name == name {
			s.Ciphertext = append([]byte(nil), s.Ciphertext...)
			s.Nonce = append([]byte(nil), s.Nonce...)
			return s, nil
		}
	}
	return model.ExtensionSecret{}, ErrNotFound
}
func secretMetadata0207(s model.ExtensionSecret) model.ExtensionSecretMetadata {
	return model.ExtensionSecretMetadata{ExtensionID: s.ExtensionID, Scope: s.Scope, ScopeID: s.ScopeID, Name: s.Name, KeyVersion: s.KeyVersion, UpdatedBy: s.UpdatedBy, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}
func (r *MemoryRepository) ListExtensionSecrets(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionSecretMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := []model.ExtensionSecretMetadata{}
	for _, s := range r.extensionSecrets {
		if s.ExtensionID != extensionID {
			continue
		}
		if scope != "" && s.Scope != scope {
			continue
		}
		if scopeID != "" && s.ScopeID != scopeID {
			continue
		}
		out = append(out, secretMetadata0207(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (r *MemoryRepository) DeleteExtensionSecret(ctx context.Context, extensionID, scope, scopeID, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, scopeID, err := normalizeSecurityScope0207(scope, scopeID)
	if err != nil {
		return err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	name = strings.TrimSpace(name)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i, s := range r.extensionSecrets {
		if s.ExtensionID == extensionID && s.Scope == scope && s.ScopeID == scopeID && s.Name == name {
			r.extensionSecrets = append(r.extensionSecrets[:i], r.extensionSecrets[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (r *SQLRepository) ListExtensionPermissionGrants(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionPermissionGrant, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	q := `SELECT extension_id,scope,scope_id,permission,granted_by,reason,created_at,updated_at FROM extension_permission_grants WHERE extension_id=$1`
	args := []any{strings.ToLower(strings.TrimSpace(extensionID))}
	if strings.TrimSpace(scope) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(scope)))
		q += fmt.Sprintf(" AND scope=$%d", len(args))
	}
	if strings.TrimSpace(scopeID) != "" {
		args = append(args, strings.TrimSpace(scopeID))
		q += fmt.Sprintf(" AND scope_id=$%d", len(args))
	}
	q += ` ORDER BY scope,scope_id,permission`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionPermissionGrant{}
	for rows.Next() {
		var g model.ExtensionPermissionGrant
		if err := rows.Scan(&g.ExtensionID, &g.Scope, &g.ScopeID, &g.Permission, &g.GrantedBy, &g.Reason, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (r *SQLRepository) GrantExtensionPermission(ctx context.Context, grant model.ExtensionPermissionGrant) (model.ExtensionPermissionGrant, error) {
	if err := r.check(); err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	g, err := normalizeGrant0207(grant)
	if err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	err = r.db.QueryRowContext(ctx, `INSERT INTO extension_permission_grants(extension_id,scope,scope_id,permission,granted_by,reason) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(extension_id,scope,scope_id,permission) DO UPDATE SET granted_by=EXCLUDED.granted_by,reason=EXCLUDED.reason,updated_at=now() RETURNING created_at,updated_at`, g.ExtensionID, g.Scope, g.ScopeID, g.Permission, g.GrantedBy, g.Reason).Scan(&g.CreatedAt, &g.UpdatedAt)
	return g, err
}
func (r *SQLRepository) RevokeExtensionPermission(ctx context.Context, extensionID, scope, scopeID, permission string) error {
	if err := r.check(); err != nil {
		return err
	}
	scope, scopeID, err := normalizeSecurityScope0207(scope, scopeID)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM extension_permission_grants WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 AND permission=$4`, strings.ToLower(strings.TrimSpace(extensionID)), scope, scopeID, strings.ToLower(strings.TrimSpace(permission)))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (r *SQLRepository) PutExtensionSecret(ctx context.Context, secret model.ExtensionSecret) (model.ExtensionSecret, error) {
	if err := r.check(); err != nil {
		return model.ExtensionSecret{}, err
	}
	s, err := normalizeSecret0207(secret)
	if err != nil {
		return model.ExtensionSecret{}, err
	}
	err = r.db.QueryRowContext(ctx, `INSERT INTO extension_secrets(extension_id,scope,scope_id,name,ciphertext,nonce,key_version,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(extension_id,scope,scope_id,name) DO UPDATE SET ciphertext=EXCLUDED.ciphertext,nonce=EXCLUDED.nonce,key_version=EXCLUDED.key_version,updated_by=EXCLUDED.updated_by,updated_at=now() RETURNING created_at,updated_at`, s.ExtensionID, s.Scope, s.ScopeID, s.Name, s.Ciphertext, s.Nonce, s.KeyVersion, s.UpdatedBy).Scan(&s.CreatedAt, &s.UpdatedAt)
	return s, err
}
func (r *SQLRepository) GetExtensionSecret(ctx context.Context, extensionID, scope, scopeID, name string) (model.ExtensionSecret, error) {
	if err := r.check(); err != nil {
		return model.ExtensionSecret{}, err
	}
	scope, scopeID, err := normalizeSecurityScope0207(scope, scopeID)
	if err != nil {
		return model.ExtensionSecret{}, err
	}
	var s model.ExtensionSecret
	err = r.db.QueryRowContext(ctx, `SELECT extension_id,scope,scope_id,name,ciphertext,nonce,key_version,updated_by,created_at,updated_at FROM extension_secrets WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 AND name=$4`, strings.ToLower(strings.TrimSpace(extensionID)), scope, scopeID, strings.TrimSpace(name)).Scan(&s.ExtensionID, &s.Scope, &s.ScopeID, &s.Name, &s.Ciphertext, &s.Nonce, &s.KeyVersion, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionSecret{}, ErrNotFound
	}
	return s, err
}
func (r *SQLRepository) ListExtensionSecrets(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionSecretMetadata, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	q := `SELECT extension_id,scope,scope_id,name,key_version,updated_by,created_at,updated_at FROM extension_secrets WHERE extension_id=$1`
	args := []any{strings.ToLower(strings.TrimSpace(extensionID))}
	if strings.TrimSpace(scope) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(scope)))
		q += fmt.Sprintf(" AND scope=$%d", len(args))
	}
	if strings.TrimSpace(scopeID) != "" {
		args = append(args, strings.TrimSpace(scopeID))
		q += fmt.Sprintf(" AND scope_id=$%d", len(args))
	}
	q += ` ORDER BY scope,scope_id,name`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ExtensionSecretMetadata{}
	for rows.Next() {
		var s model.ExtensionSecretMetadata
		if err := rows.Scan(&s.ExtensionID, &s.Scope, &s.ScopeID, &s.Name, &s.KeyVersion, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (r *SQLRepository) DeleteExtensionSecret(ctx context.Context, extensionID, scope, scopeID, name string) error {
	if err := r.check(); err != nil {
		return err
	}
	scope, scopeID, err := normalizeSecurityScope0207(scope, scopeID)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM extension_secrets WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 AND name=$4`, strings.ToLower(strings.TrimSpace(extensionID)), scope, scopeID, strings.TrimSpace(name))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

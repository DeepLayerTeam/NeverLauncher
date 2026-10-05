package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var (
	extensionID0201         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	extensionSemver0201     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	extensionPermission0201 = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,127}$`)
)

// NormalizeExtensionManifest validates and canonicalizes a NeverExtensions manifest.
// Registry/package verification uses the same normalization as persistence so
// package identity and database identity cannot diverge.
func NormalizeExtensionManifest(in model.ExtensionManifest) (model.ExtensionManifest, string, error) {
	return normalizeExtensionManifest0201(in)
}

func normalizeExtensionManifest0201(in model.ExtensionManifest) (model.ExtensionManifest, string, error) {
	m := in
	m.SchemaVersion = strings.TrimSpace(m.SchemaVersion)
	m.ID = strings.ToLower(strings.TrimSpace(m.ID))
	m.Name = strings.TrimSpace(m.Name)
	m.Version = strings.TrimSpace(m.Version)
	m.Publisher = strings.TrimSpace(m.Publisher)
	m.Description = strings.TrimSpace(m.Description)
	m.Homepage = strings.TrimSpace(m.Homepage)
	m.Repository = strings.TrimSpace(m.Repository)
	m.API = strings.TrimSpace(m.API)
	if m.SchemaVersion == "" {
		m.SchemaVersion = "2.0"
	}
	if m.SchemaVersion != "2.0" {
		return model.ExtensionManifest{}, "", fmt.Errorf("unsupported extension schemaVersion %q; expected 2.0", m.SchemaVersion)
	}
	if !extensionID0201.MatchString(m.ID) {
		return model.ExtensionManifest{}, "", fmt.Errorf("invalid extension id %q", m.ID)
	}
	if m.Name == "" || len(m.Name) > 160 {
		return model.ExtensionManifest{}, "", fmt.Errorf("extension name must contain 1..160 characters")
	}
	if m.Publisher == "" || len(m.Publisher) > 160 {
		return model.ExtensionManifest{}, "", fmt.Errorf("extension publisher must contain 1..160 characters")
	}
	if !extensionSemver0201.MatchString(m.Version) {
		return model.ExtensionManifest{}, "", fmt.Errorf("extension version %q is not supported semver", m.Version)
	}
	if m.API == "" || len(m.API) > 64 {
		return model.ExtensionManifest{}, "", fmt.Errorf("extension api is required")
	}
	if len(m.Targets) == 0 {
		return model.ExtensionManifest{}, "", fmt.Errorf("extension must declare at least one target")
	}
	targets := make([]model.ExtensionTarget, 0, len(m.Targets))
	seenTargets := map[string]struct{}{}
	for _, target := range m.Targets {
		target.Kind = strings.ToLower(strings.TrimSpace(target.Kind))
		target.Entrypoint = strings.TrimSpace(target.Entrypoint)
		if target.Kind != "backend" && target.Kind != "admin" && target.Kind != "desktop" && target.Kind != "cli" {
			return model.ExtensionManifest{}, "", fmt.Errorf("unsupported extension target %q", target.Kind)
		}
		if target.Entrypoint == "" || strings.HasPrefix(target.Entrypoint, "/") || strings.Contains(target.Entrypoint, "\\") {
			return model.ExtensionManifest{}, "", fmt.Errorf("target %s has invalid entrypoint", target.Kind)
		}
		for _, part := range strings.Split(target.Entrypoint, "/") {
			if part == "" || part == "." || part == ".." {
				return model.ExtensionManifest{}, "", fmt.Errorf("target %s entrypoint must be a clean relative path", target.Kind)
			}
		}
		if _, duplicate := seenTargets[target.Kind]; duplicate {
			return model.ExtensionManifest{}, "", fmt.Errorf("duplicate extension target %q", target.Kind)
		}
		seenTargets[target.Kind] = struct{}{}
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Kind < targets[j].Kind })
	m.Targets = targets

	normalizeUnique := func(values []string, validator *regexp.Regexp, field string) ([]string, error) {
		out := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			if validator != nil && !validator.MatchString(value) {
				return nil, fmt.Errorf("invalid %s %q", field, value)
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
		sort.Strings(out)
		return out, nil
	}
	var err error
	m.Permissions, err = normalizeUnique(m.Permissions, extensionPermission0201, "permission")
	if err != nil {
		return model.ExtensionManifest{}, "", err
	}
	m.Hooks, err = normalizeUnique(m.Hooks, extensionPermission0201, "hook")
	if err != nil {
		return model.ExtensionManifest{}, "", err
	}

	deps := make([]model.ExtensionDependency, 0, len(m.Dependencies))
	seenDeps := map[string]struct{}{}
	for _, dep := range m.Dependencies {
		dep.ID = strings.ToLower(strings.TrimSpace(dep.ID))
		dep.Version = strings.TrimSpace(dep.Version)
		if !extensionID0201.MatchString(dep.ID) {
			return model.ExtensionManifest{}, "", fmt.Errorf("invalid dependency id %q", dep.ID)
		}
		if dep.ID == m.ID {
			return model.ExtensionManifest{}, "", fmt.Errorf("extension cannot depend on itself")
		}
		if dep.Version == "" || len(dep.Version) > 128 {
			return model.ExtensionManifest{}, "", fmt.Errorf("dependency %s requires a version constraint", dep.ID)
		}
		if _, ok := seenDeps[dep.ID]; ok {
			return model.ExtensionManifest{}, "", fmt.Errorf("duplicate dependency %q", dep.ID)
		}
		seenDeps[dep.ID] = struct{}{}
		deps = append(deps, dep)
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].ID < deps[j].ID })
	m.Dependencies = deps
	if m.Metadata == nil {
		m.Metadata = map[string]string{}
	}

	canonical, err := json.Marshal(m)
	if err != nil {
		return model.ExtensionManifest{}, "", fmt.Errorf("marshal canonical extension manifest: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return m, hex.EncodeToString(digest[:]), nil
}

func extensionVersionFromManifest0201(manifest model.ExtensionManifest, digest string, createdAt time.Time) model.ExtensionVersion {
	return model.ExtensionVersion{
		ExtensionID:    manifest.ID,
		Version:        manifest.Version,
		SchemaVersion:  manifest.SchemaVersion,
		API:            manifest.API,
		Manifest:       manifest,
		ManifestSHA256: digest,
		CreatedAt:      createdAt,
	}
}

func normalizeExtensionInstall0201(in model.ExtensionInstall) (model.ExtensionInstall, error) {
	item := in
	item.ExtensionID = strings.ToLower(strings.TrimSpace(item.ExtensionID))
	item.Scope = strings.ToLower(strings.TrimSpace(item.Scope))
	item.ScopeID = strings.TrimSpace(item.ScopeID)
	item.Version = strings.TrimSpace(item.Version)
	item.Source = strings.TrimSpace(item.Source)
	if !extensionID0201.MatchString(item.ExtensionID) {
		return model.ExtensionInstall{}, fmt.Errorf("invalid extension id %q", item.ExtensionID)
	}
	if !extensionSemver0201.MatchString(item.Version) {
		return model.ExtensionInstall{}, fmt.Errorf("invalid extension version %q", item.Version)
	}
	if item.Scope == "" {
		item.Scope = "global"
	}
	if item.Scope != "global" && item.Scope != "project" {
		return model.ExtensionInstall{}, fmt.Errorf("extension install scope must be global or project")
	}
	if item.Scope == "global" {
		item.ScopeID = ""
	} else if item.ScopeID == "" {
		return model.ExtensionInstall{}, fmt.Errorf("project extension install requires scopeId")
	}
	if item.Source == "" {
		item.Source = "local"
	}
	return item, nil
}

func (r *MemoryRepository) ListExtensions(ctx context.Context) ([]model.Extension, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := append([]model.Extension(nil), r.extensions...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (r *MemoryRepository) GetExtension(ctx context.Context, id string) (model.Extension, error) {
	if err := ctx.Err(); err != nil {
		return model.Extension{}, err
	}
	id = strings.ToLower(strings.TrimSpace(id))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, item := range r.extensions {
		if item.ID == id {
			return item, nil
		}
	}
	return model.Extension{}, ErrNotFound
}

func (r *MemoryRepository) ListExtensionVersions(ctx context.Context, extensionID string) ([]model.ExtensionVersion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionVersion, 0)
	for _, item := range r.extensionVersions {
		if item.ExtensionID == extensionID {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Version > out[j].Version
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (r *MemoryRepository) GetExtensionVersion(ctx context.Context, extensionID, version string) (model.ExtensionVersion, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionVersion{}, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	version = strings.TrimSpace(version)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, item := range r.extensionVersions {
		if item.ExtensionID == extensionID && item.Version == version {
			return item, nil
		}
	}
	return model.ExtensionVersion{}, ErrNotFound
}

func (r *MemoryRepository) ListExtensionPermissions(ctx context.Context, extensionID, version string) ([]string, error) {
	item, err := r.GetExtensionVersion(ctx, extensionID, version)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), item.Manifest.Permissions...), nil
}

func (r *MemoryRepository) ListExtensionDependencies(ctx context.Context, extensionID, version string) ([]model.ExtensionDependency, error) {
	item, err := r.GetExtensionVersion(ctx, extensionID, version)
	if err != nil {
		return nil, err
	}
	return append([]model.ExtensionDependency(nil), item.Manifest.Dependencies...), nil
}

func (r *MemoryRepository) SaveExtensionVersion(ctx context.Context, manifest model.ExtensionManifest) (model.ExtensionVersion, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionVersion{}, err
	}
	manifest, digest, err := normalizeExtensionManifest0201(manifest)
	if err != nil {
		return model.ExtensionVersion{}, err
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()

	for _, item := range r.extensionVersions {
		if item.ExtensionID == manifest.ID && item.Version == manifest.Version {
			if item.ManifestSHA256 != digest {
				return model.ExtensionVersion{}, fmt.Errorf("%w: extension %s version %s already exists with another manifest", ErrImmutable, manifest.ID, manifest.Version)
			}
			return item, nil
		}
	}

	identityFound := false
	for i := range r.extensions {
		if r.extensions[i].ID != manifest.ID {
			continue
		}
		identityFound = true
		if r.extensions[i].Publisher != manifest.Publisher {
			return model.ExtensionVersion{}, fmt.Errorf("%w: extension publisher is immutable", ErrConflict)
		}
		r.extensions[i].Name = manifest.Name
		r.extensions[i].Description = manifest.Description
		r.extensions[i].Homepage = manifest.Homepage
		r.extensions[i].Repository = manifest.Repository
		r.extensions[i].UpdatedAt = now
		break
	}
	if !identityFound {
		r.extensions = append(r.extensions, model.Extension{ID: manifest.ID, Name: manifest.Name, Publisher: manifest.Publisher, Description: manifest.Description, Homepage: manifest.Homepage, Repository: manifest.Repository, CreatedAt: now, UpdatedAt: now})
	}
	item := extensionVersionFromManifest0201(manifest, digest, now)
	r.extensionVersions = append(r.extensionVersions, item)
	return item, nil
}

func (r *MemoryRepository) ListExtensionInstalls(ctx context.Context, scope, scopeID string) ([]model.ExtensionInstall, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionInstall, 0)
	for _, item := range r.extensionInstalls {
		if scope != "" && item.Scope != scope {
			continue
		}
		if scopeID != "" && item.ScopeID != scopeID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExtensionID < out[j].ExtensionID })
	return out, nil
}

func (r *MemoryRepository) GetExtensionInstall(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionInstall, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionInstall{}, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "global"
	}
	if scope == "global" {
		scopeID = ""
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, item := range r.extensionInstalls {
		if item.ExtensionID == extensionID && item.Scope == scope && item.ScopeID == scopeID {
			return item, nil
		}
	}
	return model.ExtensionInstall{}, ErrNotFound
}

func (r *MemoryRepository) SaveExtensionInstall(ctx context.Context, install model.ExtensionInstall) (model.ExtensionInstall, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionInstall{}, err
	}
	install, err := normalizeExtensionInstall0201(install)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	foundVersion := false
	for _, version := range r.extensionVersions {
		if version.ExtensionID == install.ExtensionID && version.Version == install.Version {
			foundVersion = true
			break
		}
	}
	if !foundVersion {
		return model.ExtensionInstall{}, ErrNotFound
	}
	for i := range r.extensionInstalls {
		if r.extensionInstalls[i].ExtensionID == install.ExtensionID && r.extensionInstalls[i].Scope == install.Scope && r.extensionInstalls[i].ScopeID == install.ScopeID {
			install.InstalledAt = r.extensionInstalls[i].InstalledAt
			install.UpdatedAt = now
			r.extensionInstalls[i] = install
			return install, nil
		}
	}
	install.InstalledAt = now
	install.UpdatedAt = now
	r.extensionInstalls = append(r.extensionInstalls, install)
	return install, nil
}

func (r *MemoryRepository) DeleteExtensionInstall(ctx context.Context, extensionID, scope, scopeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "global"
	}
	if scope == "global" {
		scopeID = ""
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i, item := range r.extensionInstalls {
		if item.ExtensionID == extensionID && item.Scope == scope && item.ScopeID == scopeID {
			r.extensionInstalls = append(r.extensionInstalls[:i], r.extensionInstalls[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (r *SQLRepository) ListExtensions(ctx context.Context) ([]model.Extension, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,publisher,description,homepage,repository,created_at,updated_at FROM extensions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.Extension, 0)
	for rows.Next() {
		var item model.Extension
		if err := rows.Scan(&item.ID, &item.Name, &item.Publisher, &item.Description, &item.Homepage, &item.Repository, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *SQLRepository) GetExtension(ctx context.Context, id string) (model.Extension, error) {
	if err := r.check(); err != nil {
		return model.Extension{}, err
	}
	var item model.Extension
	err := r.db.QueryRowContext(ctx, `SELECT id,name,publisher,description,homepage,repository,created_at,updated_at FROM extensions WHERE id=$1`, strings.ToLower(strings.TrimSpace(id))).Scan(&item.ID, &item.Name, &item.Publisher, &item.Description, &item.Homepage, &item.Repository, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Extension{}, ErrNotFound
	}
	return item, err
}

func scanExtensionVersion0201(scanner interface{ Scan(...any) error }) (model.ExtensionVersion, error) {
	var item model.ExtensionVersion
	var raw []byte
	if err := scanner.Scan(&item.ExtensionID, &item.Version, &item.SchemaVersion, &item.API, &raw, &item.ManifestSHA256, &item.CreatedAt); err != nil {
		return model.ExtensionVersion{}, err
	}
	if err := json.Unmarshal(raw, &item.Manifest); err != nil {
		return model.ExtensionVersion{}, fmt.Errorf("decode persisted extension manifest %s@%s: %w", item.ExtensionID, item.Version, err)
	}
	normalized, digest, err := normalizeExtensionManifest0201(item.Manifest)
	if err != nil {
		return model.ExtensionVersion{}, fmt.Errorf("persisted extension manifest %s@%s is invalid: %w", item.ExtensionID, item.Version, err)
	}
	if normalized.ID != item.ExtensionID || normalized.Version != item.Version || normalized.SchemaVersion != item.SchemaVersion || normalized.API != item.API || digest != item.ManifestSHA256 {
		return model.ExtensionVersion{}, fmt.Errorf("persisted extension manifest integrity mismatch for %s@%s", item.ExtensionID, item.Version)
	}
	item.Manifest = normalized
	return item, nil
}

func (r *SQLRepository) ListExtensionVersions(ctx context.Context, extensionID string) ([]model.ExtensionVersion, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT extension_id,version,schema_version,api,manifest,manifest_sha256,created_at FROM extension_versions WHERE extension_id=$1 ORDER BY created_at DESC,version DESC`, strings.ToLower(strings.TrimSpace(extensionID)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionVersion, 0)
	for rows.Next() {
		item, err := scanExtensionVersion0201(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *SQLRepository) GetExtensionVersion(ctx context.Context, extensionID, version string) (model.ExtensionVersion, error) {
	if err := r.check(); err != nil {
		return model.ExtensionVersion{}, err
	}
	item, err := scanExtensionVersion0201(r.db.QueryRowContext(ctx, `SELECT extension_id,version,schema_version,api,manifest,manifest_sha256,created_at FROM extension_versions WHERE extension_id=$1 AND version=$2`, strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionVersion{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) ListExtensionPermissions(ctx context.Context, extensionID, version string) ([]string, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT permission FROM extension_permissions WHERE extension_id=$1 AND version=$2 ORDER BY permission`, strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		out = append(out, permission)
	}
	return out, rows.Err()
}

func (r *SQLRepository) ListExtensionDependencies(ctx context.Context, extensionID, version string) ([]model.ExtensionDependency, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT dependency_id,version_constraint,optional FROM extension_dependencies WHERE extension_id=$1 AND version=$2 ORDER BY dependency_id`, strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionDependency, 0)
	for rows.Next() {
		var dep model.ExtensionDependency
		if err := rows.Scan(&dep.ID, &dep.Version, &dep.Optional); err != nil {
			return nil, err
		}
		out = append(out, dep)
	}
	return out, rows.Err()
}

func (r *SQLRepository) SaveExtensionVersion(ctx context.Context, manifest model.ExtensionManifest) (model.ExtensionVersion, error) {
	if err := r.check(); err != nil {
		return model.ExtensionVersion{}, err
	}
	manifest, digest, err := normalizeExtensionManifest0201(manifest)
	if err != nil {
		return model.ExtensionVersion{}, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return model.ExtensionVersion{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.ExtensionVersion{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `INSERT INTO extensions(id,name,publisher,description,homepage,repository) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING`, manifest.ID, manifest.Name, manifest.Publisher, manifest.Description, manifest.Homepage, manifest.Repository); err != nil {
		return model.ExtensionVersion{}, err
	}
	var publisher string
	if err := tx.QueryRowContext(ctx, `SELECT publisher FROM extensions WHERE id=$1 FOR UPDATE`, manifest.ID).Scan(&publisher); err != nil {
		return model.ExtensionVersion{}, err
	}
	if publisher != manifest.Publisher {
		return model.ExtensionVersion{}, fmt.Errorf("%w: extension publisher is immutable", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE extensions SET name=$2,description=$3,homepage=$4,repository=$5,updated_at=now() WHERE id=$1`, manifest.ID, manifest.Name, manifest.Description, manifest.Homepage, manifest.Repository); err != nil {
		return model.ExtensionVersion{}, err
	}

	var existingDigest string
	var existingCreated time.Time
	err = tx.QueryRowContext(ctx, `SELECT manifest_sha256,created_at FROM extension_versions WHERE extension_id=$1 AND version=$2`, manifest.ID, manifest.Version).Scan(&existingDigest, &existingCreated)
	if err == nil {
		if existingDigest != digest {
			return model.ExtensionVersion{}, fmt.Errorf("%w: extension %s version %s already exists with another manifest", ErrImmutable, manifest.ID, manifest.Version)
		}
		if err := tx.Commit(); err != nil {
			return model.ExtensionVersion{}, err
		}
		return extensionVersionFromManifest0201(manifest, digest, existingCreated), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionVersion{}, err
	}

	var created time.Time
	if err := tx.QueryRowContext(ctx, `INSERT INTO extension_versions(extension_id,version,schema_version,api,manifest,manifest_sha256) VALUES($1,$2,$3,$4,$5::jsonb,$6) RETURNING created_at`, manifest.ID, manifest.Version, manifest.SchemaVersion, manifest.API, string(raw), digest).Scan(&created); err != nil {
		return model.ExtensionVersion{}, err
	}
	for _, permission := range manifest.Permissions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_permissions(extension_id,version,permission) VALUES($1,$2,$3)`, manifest.ID, manifest.Version, permission); err != nil {
			return model.ExtensionVersion{}, err
		}
	}
	for _, dep := range manifest.Dependencies {
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_dependencies(extension_id,version,dependency_id,version_constraint,optional) VALUES($1,$2,$3,$4,$5)`, manifest.ID, manifest.Version, dep.ID, dep.Version, dep.Optional); err != nil {
			return model.ExtensionVersion{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.ExtensionVersion{}, err
	}
	return extensionVersionFromManifest0201(manifest, digest, created), nil
}

func scanExtensionInstall0201(scanner interface{ Scan(...any) error }) (model.ExtensionInstall, error) {
	var item model.ExtensionInstall
	if err := scanner.Scan(&item.ExtensionID, &item.Scope, &item.ScopeID, &item.Version, &item.Enabled, &item.Source, &item.InstalledAt, &item.UpdatedAt); err != nil {
		return model.ExtensionInstall{}, err
	}
	return item, nil
}

func (r *SQLRepository) ListExtensionInstalls(ctx context.Context, scope, scopeID string) ([]model.ExtensionInstall, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	query := `SELECT extension_id,scope,scope_id,version,enabled,source,installed_at,updated_at FROM extension_installs WHERE 1=1`
	args := []any{}
	if scope != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(scope)))
		query += fmt.Sprintf(" AND scope=$%d", len(args))
	}
	if scopeID != "" {
		args = append(args, strings.TrimSpace(scopeID))
		query += fmt.Sprintf(" AND scope_id=$%d", len(args))
	}
	query += ` ORDER BY extension_id`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionInstall, 0)
	for rows.Next() {
		item, err := scanExtensionInstall0201(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *SQLRepository) GetExtensionInstall(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionInstall, error) {
	if err := r.check(); err != nil {
		return model.ExtensionInstall{}, err
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "global"
	}
	if scope == "global" {
		scopeID = ""
	}
	item, err := scanExtensionInstall0201(r.db.QueryRowContext(ctx, `SELECT extension_id,scope,scope_id,version,enabled,source,installed_at,updated_at FROM extension_installs WHERE extension_id=$1 AND scope=$2 AND scope_id=$3`, strings.ToLower(strings.TrimSpace(extensionID)), scope, strings.TrimSpace(scopeID)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionInstall{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) SaveExtensionInstall(ctx context.Context, install model.ExtensionInstall) (model.ExtensionInstall, error) {
	if err := r.check(); err != nil {
		return model.ExtensionInstall{}, err
	}
	install, err := normalizeExtensionInstall0201(install)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	var versionExists bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM extension_versions WHERE extension_id=$1 AND version=$2)`, install.ExtensionID, install.Version).Scan(&versionExists); err != nil {
		return model.ExtensionInstall{}, err
	}
	if !versionExists {
		return model.ExtensionInstall{}, ErrNotFound
	}
	item, err := scanExtensionInstall0201(r.db.QueryRowContext(ctx, `INSERT INTO extension_installs(extension_id,scope,scope_id,version,enabled,source)
VALUES($1,$2,$3,$4,$5,$6)
ON CONFLICT(extension_id,scope,scope_id) DO UPDATE SET version=EXCLUDED.version,enabled=EXCLUDED.enabled,source=EXCLUDED.source,updated_at=now()
RETURNING extension_id,scope,scope_id,version,enabled,source,installed_at,updated_at`, install.ExtensionID, install.Scope, install.ScopeID, install.Version, install.Enabled, install.Source))
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	return item, nil
}

func (r *SQLRepository) DeleteExtensionInstall(ctx context.Context, extensionID, scope, scopeID string) error {
	if err := r.check(); err != nil {
		return err
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "global"
	}
	if scope == "global" {
		scopeID = ""
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM extension_installs WHERE extension_id=$1 AND scope=$2 AND scope_id=$3`, strings.ToLower(strings.TrimSpace(extensionID)), scope, strings.TrimSpace(scopeID))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

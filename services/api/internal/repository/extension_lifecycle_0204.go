package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var lifecycleOperation0204 = map[string]struct{}{
	"install": {}, "enable": {}, "disable": {}, "update": {}, "rollback": {}, "uninstall": {},
}

func normalizeLifecycleScope0204(scope, scopeID string) (string, string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	if scope == "" {
		scope = "global"
	}
	switch scope {
	case "global":
		scopeID = ""
	case "project":
		if scopeID == "" {
			return "", "", errors.New("project extension lifecycle requires scopeId")
		}
	default:
		return "", "", errors.New("extension lifecycle scope must be global or project")
	}
	return scope, scopeID, nil
}

func normalizeLifecycleState0204(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case model.ExtensionInstallStateAbsent, model.ExtensionInstallStateDisabled, model.ExtensionInstallStateEnabled, model.ExtensionInstallStateError:
		return v, nil
	default:
		return "", fmt.Errorf("invalid extension lifecycle state %q", v)
	}
}

func normalizeLifecycleTransition0204(in model.ExtensionLifecycleTransition) (model.ExtensionLifecycleTransition, error) {
	in.ExtensionID = strings.ToLower(strings.TrimSpace(in.ExtensionID))
	if !extensionID0201.MatchString(in.ExtensionID) {
		return model.ExtensionLifecycleTransition{}, fmt.Errorf("invalid extension id %q", in.ExtensionID)
	}
	var err error
	in.Scope, in.ScopeID, err = normalizeLifecycleScope0204(in.Scope, in.ScopeID)
	if err != nil {
		return model.ExtensionLifecycleTransition{}, err
	}
	in.DesiredVersion = strings.TrimSpace(in.DesiredVersion)
	in.CurrentVersion = strings.TrimSpace(in.CurrentVersion)
	in.PackageIdentity = strings.ToLower(strings.TrimSpace(in.PackageIdentity))
	in.CurrentPackageIdentity = strings.ToLower(strings.TrimSpace(in.CurrentPackageIdentity))
	in.PreviousVersion = strings.TrimSpace(in.PreviousVersion)
	in.PreviousPackageIdentity = strings.ToLower(strings.TrimSpace(in.PreviousPackageIdentity))
	in.Source = strings.TrimSpace(in.Source)
	in.LastError = strings.TrimSpace(in.LastError)
	in.Operation = strings.ToLower(strings.TrimSpace(in.Operation))
	in.BackupPath = strings.TrimSpace(in.BackupPath)
	if _, ok := lifecycleOperation0204[in.Operation]; !ok {
		return model.ExtensionLifecycleTransition{}, fmt.Errorf("invalid lifecycle operation %q", in.Operation)
	}
	if in.DesiredVersion == "" || !extensionSemver0201.MatchString(in.DesiredVersion) {
		return model.ExtensionLifecycleTransition{}, errors.New("desired lifecycle version must be semver")
	}
	if in.CurrentVersion != "" && !extensionSemver0201.MatchString(in.CurrentVersion) {
		return model.ExtensionLifecycleTransition{}, errors.New("current lifecycle version must be semver or empty")
	}
	in.DesiredState, err = normalizeLifecycleState0204(in.DesiredState)
	if err != nil {
		return model.ExtensionLifecycleTransition{}, err
	}
	in.CurrentState, err = normalizeLifecycleState0204(in.CurrentState)
	if err != nil {
		return model.ExtensionLifecycleTransition{}, err
	}
	if in.CurrentState == model.ExtensionInstallStateAbsent {
		if in.CurrentVersion != "" || in.CurrentPackageIdentity != "" || in.Enabled {
			return model.ExtensionLifecycleTransition{}, errors.New("absent current state cannot have version/package/enabled")
		}
	} else if in.CurrentVersion == "" {
		return model.ExtensionLifecycleTransition{}, errors.New("non-absent current state requires current version")
	}
	if (in.CurrentState == model.ExtensionInstallStateEnabled) != in.Enabled {
		return model.ExtensionLifecycleTransition{}, errors.New("enabled flag must match current state")
	}
	if in.PackageIdentity != "" && !registryIdentity0203.MatchString(in.PackageIdentity) {
		return model.ExtensionLifecycleTransition{}, errors.New("invalid desired package identity")
	}
	if in.CurrentPackageIdentity != "" && !registryIdentity0203.MatchString(in.CurrentPackageIdentity) {
		return model.ExtensionLifecycleTransition{}, errors.New("invalid current package identity")
	}
	if in.PreviousPackageIdentity != "" && !registryIdentity0203.MatchString(in.PreviousPackageIdentity) {
		return model.ExtensionLifecycleTransition{}, errors.New("invalid previous package identity")
	}
	if in.Source == "" {
		in.Source = "registry"
	}
	if in.ExpectedGeneration < 0 {
		return model.ExtensionLifecycleTransition{}, errors.New("expected generation cannot be negative")
	}
	return in, nil
}

func lifecycleInstallFromTransition0204(in model.ExtensionLifecycleTransition, generation int64, installedAt, updatedAt time.Time) model.ExtensionInstall {
	return model.ExtensionInstall{
		ExtensionID: in.ExtensionID, Scope: in.Scope, ScopeID: in.ScopeID,
		Version: in.DesiredVersion, DesiredVersion: in.DesiredVersion, CurrentVersion: in.CurrentVersion,
		DesiredState: in.DesiredState, CurrentState: in.CurrentState, Enabled: in.Enabled,
		PackageIdentity: in.PackageIdentity, CurrentPackageIdentity: in.CurrentPackageIdentity,
		PreviousVersion: in.PreviousVersion, PreviousPackageIdentity: in.PreviousPackageIdentity,
		Generation: generation, Source: in.Source, LastError: in.LastError,
		InstalledAt: installedAt, UpdatedAt: updatedAt, ActivatedAt: in.ActivatedAt,
	}
}

func (r *MemoryRepository) GetExtensionInstallState(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionInstall, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionInstall{}, err
	}
	scope, scopeID, err := normalizeLifecycleScope0204(scope, scopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, item := range r.extensionInstalls {
		if item.ExtensionID == extensionID && item.Scope == scope && item.ScopeID == scopeID {
			return item, nil
		}
	}
	return model.ExtensionInstall{}, ErrNotFound
}

func (r *MemoryRepository) ListExtensionInstallStates(ctx context.Context, scope, scopeID string) ([]model.ExtensionInstall, error) {
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope == out[j].Scope && out[i].ScopeID == out[j].ScopeID {
			return out[i].ExtensionID < out[j].ExtensionID
		}
		if out[i].Scope == out[j].Scope {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Scope < out[j].Scope
	})
	return out, nil
}

func (r *MemoryRepository) TransitionExtensionInstall(ctx context.Context, transition model.ExtensionLifecycleTransition) (model.ExtensionInstall, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionInstall{}, err
	}
	transition, err := normalizeLifecycleTransition0204(transition)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	idx := -1
	var before model.ExtensionInstall
	for i, item := range r.extensionInstalls {
		if item.ExtensionID == transition.ExtensionID && item.Scope == transition.Scope && item.ScopeID == transition.ScopeID {
			idx = i
			before = item
			break
		}
	}
	if idx < 0 {
		if transition.ExpectedGeneration != 0 {
			return model.ExtensionInstall{}, fmt.Errorf("%w: lifecycle generation changed", ErrConflict)
		}
		found := false
		for _, v := range r.extensionVersions {
			if v.ExtensionID == transition.ExtensionID && v.Version == transition.DesiredVersion {
				found = true
				break
			}
		}
		if !found {
			return model.ExtensionInstall{}, ErrNotFound
		}
		before = model.ExtensionInstall{ExtensionID: transition.ExtensionID, Scope: transition.Scope, ScopeID: transition.ScopeID, DesiredState: model.ExtensionInstallStateAbsent, CurrentState: model.ExtensionInstallStateAbsent, Generation: 0}
	} else if before.Generation != transition.ExpectedGeneration {
		return model.ExtensionInstall{}, fmt.Errorf("%w: lifecycle generation changed: expected=%d current=%d", ErrConflict, transition.ExpectedGeneration, before.Generation)
	}
	foundDesired := false
	foundCurrent := transition.CurrentVersion == ""
	for _, v := range r.extensionVersions {
		if v.ExtensionID == transition.ExtensionID && v.Version == transition.DesiredVersion {
			foundDesired = true
		}
		if transition.CurrentVersion != "" && v.ExtensionID == transition.ExtensionID && v.Version == transition.CurrentVersion {
			foundCurrent = true
		}
	}
	if !foundDesired || !foundCurrent {
		return model.ExtensionInstall{}, ErrNotFound
	}
	now := time.Now().UTC()
	installedAt := before.InstalledAt
	if installedAt.IsZero() {
		installedAt = now
	}
	generation := before.Generation + 1
	next := lifecycleInstallFromTransition0204(transition, generation, installedAt, now)
	if idx < 0 {
		r.extensionInstalls = append(r.extensionInstalls, next)
	} else {
		r.extensionInstalls[idx] = next
	}
	rev := model.ExtensionInstallRevision{ID: r.nextExtensionInstallRevisionID, ExtensionID: transition.ExtensionID, Scope: transition.Scope, ScopeID: transition.ScopeID, Generation: generation, Operation: transition.Operation, FromVersion: before.CurrentVersion, ToVersion: transition.CurrentVersion, FromState: before.CurrentState, ToState: transition.CurrentState, FromPackageIdentity: before.CurrentPackageIdentity, ToPackageIdentity: transition.CurrentPackageIdentity, BackupPath: transition.BackupPath, Source: transition.Source, CreatedAt: now}
	if rev.FromState == "" {
		rev.FromState = model.ExtensionInstallStateAbsent
	}
	r.nextExtensionInstallRevisionID++
	r.extensionInstallRevisions = append(r.extensionInstallRevisions, rev)
	return next, nil
}

func (r *MemoryRepository) ListExtensionInstallRevisions(ctx context.Context, extensionID, scope, scopeID string, limit int) ([]model.ExtensionInstallRevision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope, scopeID, err := normalizeLifecycleScope0204(scope, scopeID)
	if err != nil {
		return nil, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionInstallRevision, 0)
	for _, rev := range r.extensionInstallRevisions {
		if rev.ExtensionID == extensionID && rev.Scope == scope && rev.ScopeID == scopeID {
			out = append(out, rev)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Generation > out[j].Generation })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

const lifecycleSelect0204 = `SELECT extension_id,scope,scope_id,version,desired_version,current_version,desired_state,current_state,enabled,package_identity,current_package_identity,previous_version,previous_package_identity,generation,source,last_error,installed_at,updated_at,activated_at FROM extension_installs`

func scanExtensionInstallState0204(scanner interface{ Scan(...any) error }) (model.ExtensionInstall, error) {
	var item model.ExtensionInstall
	if err := scanner.Scan(&item.ExtensionID, &item.Scope, &item.ScopeID, &item.Version, &item.DesiredVersion, &item.CurrentVersion, &item.DesiredState, &item.CurrentState, &item.Enabled, &item.PackageIdentity, &item.CurrentPackageIdentity, &item.PreviousVersion, &item.PreviousPackageIdentity, &item.Generation, &item.Source, &item.LastError, &item.InstalledAt, &item.UpdatedAt, &item.ActivatedAt); err != nil {
		return model.ExtensionInstall{}, err
	}
	return item, nil
}

func (r *SQLRepository) GetExtensionInstallState(ctx context.Context, extensionID, scope, scopeID string) (model.ExtensionInstall, error) {
	if err := r.check(); err != nil {
		return model.ExtensionInstall{}, err
	}
	scope, scopeID, err := normalizeLifecycleScope0204(scope, scopeID)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	item, err := scanExtensionInstallState0204(r.db.QueryRowContext(ctx, lifecycleSelect0204+` WHERE extension_id=$1 AND scope=$2 AND scope_id=$3`, strings.ToLower(strings.TrimSpace(extensionID)), scope, scopeID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionInstall{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) ListExtensionInstallStates(ctx context.Context, scope, scopeID string) ([]model.ExtensionInstall, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	query := lifecycleSelect0204 + ` WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(scope) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(scope)))
		query += fmt.Sprintf(" AND scope=$%d", len(args))
	}
	if strings.TrimSpace(scopeID) != "" {
		args = append(args, strings.TrimSpace(scopeID))
		query += fmt.Sprintf(" AND scope_id=$%d", len(args))
	}
	query += ` ORDER BY scope,scope_id,extension_id`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionInstall, 0)
	for rows.Next() {
		item, err := scanExtensionInstallState0204(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *SQLRepository) TransitionExtensionInstall(ctx context.Context, transition model.ExtensionLifecycleTransition) (model.ExtensionInstall, error) {
	if err := r.check(); err != nil {
		return model.ExtensionInstall{}, err
	}
	transition, err := normalizeLifecycleTransition0204(transition)
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	defer tx.Rollback()
	lockKey := transition.Scope + "\x00" + transition.ScopeID + "\x00" + transition.ExtensionID
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return model.ExtensionInstall{}, err
	}
	var before model.ExtensionInstall
	before, err = scanExtensionInstallState0204(tx.QueryRowContext(ctx, lifecycleSelect0204+` WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 FOR UPDATE`, transition.ExtensionID, transition.Scope, transition.ScopeID))
	newRow := false
	if errors.Is(err, sql.ErrNoRows) {
		newRow = true
		before = model.ExtensionInstall{ExtensionID: transition.ExtensionID, Scope: transition.Scope, ScopeID: transition.ScopeID, DesiredState: model.ExtensionInstallStateAbsent, CurrentState: model.ExtensionInstallStateAbsent, Generation: 0}
	} else if err != nil {
		return model.ExtensionInstall{}, err
	}
	if before.Generation != transition.ExpectedGeneration {
		return model.ExtensionInstall{}, fmt.Errorf("%w: lifecycle generation changed: expected=%d current=%d", ErrConflict, transition.ExpectedGeneration, before.Generation)
	}
	var desiredExists, currentExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM extension_versions WHERE extension_id=$1 AND version=$2)`, transition.ExtensionID, transition.DesiredVersion).Scan(&desiredExists); err != nil {
		return model.ExtensionInstall{}, err
	}
	if !desiredExists {
		return model.ExtensionInstall{}, ErrNotFound
	}
	currentExists = transition.CurrentVersion == ""
	if !currentExists {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM extension_versions WHERE extension_id=$1 AND version=$2)`, transition.ExtensionID, transition.CurrentVersion).Scan(&currentExists); err != nil {
			return model.ExtensionInstall{}, err
		}
		if !currentExists {
			return model.ExtensionInstall{}, ErrNotFound
		}
	}
	generation := before.Generation + 1
	now := time.Now().UTC()
	installedAt := before.InstalledAt
	if installedAt.IsZero() {
		installedAt = now
	}
	if newRow {
		_, err = tx.ExecContext(ctx, `INSERT INTO extension_installs(extension_id,scope,scope_id,version,desired_version,current_version,desired_state,current_state,enabled,package_identity,current_package_identity,previous_version,previous_package_identity,generation,source,last_error,installed_at,updated_at,activated_at) VALUES($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, transition.ExtensionID, transition.Scope, transition.ScopeID, transition.DesiredVersion, transition.CurrentVersion, transition.DesiredState, transition.CurrentState, transition.Enabled, transition.PackageIdentity, transition.CurrentPackageIdentity, transition.PreviousVersion, transition.PreviousPackageIdentity, generation, transition.Source, transition.LastError, installedAt, now, transition.ActivatedAt)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE extension_installs SET version=$4,desired_version=$4,current_version=$5,desired_state=$6,current_state=$7,enabled=$8,package_identity=$9,current_package_identity=$10,previous_version=$11,previous_package_identity=$12,generation=$13,source=$14,last_error=$15,updated_at=$16,activated_at=$17 WHERE extension_id=$1 AND scope=$2 AND scope_id=$3`, transition.ExtensionID, transition.Scope, transition.ScopeID, transition.DesiredVersion, transition.CurrentVersion, transition.DesiredState, transition.CurrentState, transition.Enabled, transition.PackageIdentity, transition.CurrentPackageIdentity, transition.PreviousVersion, transition.PreviousPackageIdentity, generation, transition.Source, transition.LastError, now, transition.ActivatedAt)
	}
	if err != nil {
		return model.ExtensionInstall{}, err
	}
	fromState := before.CurrentState
	if fromState == "" {
		fromState = model.ExtensionInstallStateAbsent
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO extension_install_revisions(extension_id,scope,scope_id,generation,operation,from_version,to_version,from_state,to_state,from_package_identity,to_package_identity,backup_path,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, transition.ExtensionID, transition.Scope, transition.ScopeID, generation, transition.Operation, before.CurrentVersion, transition.CurrentVersion, fromState, transition.CurrentState, before.CurrentPackageIdentity, transition.CurrentPackageIdentity, transition.BackupPath, transition.Source); err != nil {
		return model.ExtensionInstall{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ExtensionInstall{}, err
	}
	return lifecycleInstallFromTransition0204(transition, generation, installedAt, now), nil
}

func scanInstallRevision0204(scanner interface{ Scan(...any) error }) (model.ExtensionInstallRevision, error) {
	var v model.ExtensionInstallRevision
	if err := scanner.Scan(&v.ID, &v.ExtensionID, &v.Scope, &v.ScopeID, &v.Generation, &v.Operation, &v.FromVersion, &v.ToVersion, &v.FromState, &v.ToState, &v.FromPackageIdentity, &v.ToPackageIdentity, &v.BackupPath, &v.Source, &v.CreatedAt); err != nil {
		return model.ExtensionInstallRevision{}, err
	}
	return v, nil
}
func (r *SQLRepository) ListExtensionInstallRevisions(ctx context.Context, extensionID, scope, scopeID string, limit int) ([]model.ExtensionInstallRevision, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	scope, scopeID, err := normalizeLifecycleScope0204(scope, scopeID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,extension_id,scope,scope_id,generation,operation,from_version,to_version,from_state,to_state,from_package_identity,to_package_identity,backup_path,source,created_at FROM extension_install_revisions WHERE extension_id=$1 AND scope=$2 AND scope_id=$3 ORDER BY generation DESC LIMIT $4`, strings.ToLower(strings.TrimSpace(extensionID)), scope, scopeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionInstallRevision, 0)
	for rows.Next() {
		v, err := scanInstallRevision0204(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

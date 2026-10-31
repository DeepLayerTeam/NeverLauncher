package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// UpdateDraftComponentCatalog0248 repairs intermediate draft state (optional
// files have been uploaded but are not assigned yet). It may alter ONLY the
// catalog on a draft, never the pinned profile/identity or any signed release.
// Repository-side CAS is required even if an API instance holds a package lock.
func (r *MemoryRepository) UpdateDraftComponentCatalog0248(projectID, versionID string, expected uint64, cat model.ComponentCatalog0241) (model.ReleaseVersion, error) {
	for i := range r.releases {
		release := &r.releases[i]
		if release.ID != versionID || release.ProjectID != projectID {
			continue
		}
		if release.Status != "draft" || release.Manifest.SchemaVersion != model.ManifestSchemaV3 || release.Manifest.Signature != nil {
			return model.ReleaseVersion{}, ErrImmutable
		}
		if release.Manifest.ComponentCatalog == nil || release.Manifest.ComponentCatalog.Revision != expected || cat.Revision != expected+1 {
			return model.ReleaseVersion{}, errors.New("catalog revision changed")
		}
		candidate := cloneManifest0222(release.Manifest)
		candidate.ComponentCatalog = &cat
		candidate.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := model.ValidateManifestSchema(candidate); err != nil {
			return model.ReleaseVersion{}, err
		}
		release.Manifest = cloneManifest0222(candidate)
		return cloneRelease0222(*release), nil
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *SQLRepository) UpdateDraftComponentCatalog0248(projectID, versionID string, expected uint64, cat model.ComponentCatalog0241) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	tx, err := r.db.Begin()
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	defer tx.Rollback()
	var found model.ReleaseVersion
	var raw []byte
	err = tx.QueryRow(`SELECT id,project_id,profile_id,channel,version,status,manifest,published_at FROM release_versions WHERE project_id=$1 AND id=$2 FOR UPDATE`, projectID, versionID).
		Scan(&found.ID, &found.ProjectID, &found.ProfileID, &found.Channel, &found.Version, &found.Status, &raw, &found.PublishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ReleaseVersion{}, ErrNotFound
	}
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if err = json.Unmarshal(raw, &found.Manifest); err != nil {
		return model.ReleaseVersion{}, err
	}
	if found.Status != "draft" || found.Manifest.SchemaVersion != model.ManifestSchemaV3 || found.Manifest.Signature != nil {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if found.Manifest.ComponentCatalog == nil || found.Manifest.ComponentCatalog.Revision != expected || cat.Revision != expected+1 {
		return model.ReleaseVersion{}, errors.New("catalog revision changed")
	}
	next := found.Manifest
	next.ComponentCatalog = &cat
	next.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err = model.ValidateManifestSchema(next); err != nil {
		return model.ReleaseVersion{}, fmt.Errorf("catalog validation: %w", err)
	}
	body, err := json.Marshal(next)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	res, err := tx.Exec(`UPDATE release_versions SET manifest=$1 WHERE project_id=$2 AND id=$3 AND status='draft'`, string(body), projectID, versionID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	affected, err := res.RowsAffected()
	if err != nil || affected != 1 {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return model.ReleaseVersion{}, err
	}
	found.Manifest = next
	return found, nil
}

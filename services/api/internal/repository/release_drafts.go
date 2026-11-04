package repository

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// ReleaseDraft is an editable, user-owned workflow record. It does not confer
// release permissions; callers must authorize every read and mutation.
type ReleaseDraft struct {
	ID               string    `json:"id"`
	ProjectID        string    `json:"projectId"`
	OwnerID          string    `json:"ownerId"`
	ProfileID        string    `json:"profileId"`
	Channel          string    `json:"channel"`
	Version          string    `json:"version"`
	MinecraftVersion string    `json:"minecraftVersion"`
	Loader           string    `json:"loader"`
	PackageID        string    `json:"packageId"`
	JobID            string    `json:"jobId"`
	Step             string    `json:"step"`
	Revision         int64     `json:"revision"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ReleaseDraftStore interface {
	CreateReleaseDraft(context.Context, ReleaseDraft) (ReleaseDraft, error)
	ListReleaseDrafts(context.Context, string, string) ([]ReleaseDraft, error)
	GetReleaseDraft(context.Context, string) (ReleaseDraft, error)
	UpdateReleaseDraft(context.Context, ReleaseDraft) (ReleaseDraft, error)
	DeleteReleaseDraft(context.Context, string, string) error
}

func validateDraft0218(d ReleaseDraft) error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.ProjectID) == "" || strings.TrimSpace(d.OwnerID) == "" || len(d.ID) > 128 || len(d.ProjectID) > 128 || len(d.OwnerID) > 128 || len(d.ProfileID) > 128 || len(d.Channel) > 128 || len(d.Version) > 128 || len(d.MinecraftVersion) > 64 || len(d.Loader) > 64 || len(d.PackageID) > 128 || len(d.JobID) > 128 || len(d.Step) > 32 {
		return errors.New("invalid draft identity or field length")
	}
	return nil
}
func (r *MemoryRepository) CreateReleaseDraft(_ context.Context, d ReleaseDraft) (ReleaseDraft, error) {
	if err := validateDraft0218(d); err != nil {
		return d, err
	}
	r.draftMu.Lock()
	defer r.draftMu.Unlock()
	if r.releaseDrafts == nil {
		r.releaseDrafts = make(map[string]ReleaseDraft)
	}
	if _, ok := r.releaseDrafts[d.ID]; ok {
		return d, ErrConflict
	}
	now := time.Now().UTC()
	d.Revision = 1
	d.CreatedAt = now
	d.UpdatedAt = now
	r.releaseDrafts[d.ID] = d
	return d, nil
}
func (r *MemoryRepository) ListReleaseDrafts(_ context.Context, projectID, ownerID string) ([]ReleaseDraft, error) {
	r.draftMu.Lock()
	defer r.draftMu.Unlock()
	out := []ReleaseDraft{}
	for _, d := range r.releaseDrafts {
		if d.ProjectID == projectID && d.OwnerID == ownerID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}
func (r *MemoryRepository) GetReleaseDraft(_ context.Context, id string) (ReleaseDraft, error) {
	r.draftMu.Lock()
	defer r.draftMu.Unlock()
	d, ok := r.releaseDrafts[id]
	if !ok {
		return d, ErrNotFound
	}
	return d, nil
}
func (r *MemoryRepository) UpdateReleaseDraft(_ context.Context, d ReleaseDraft) (ReleaseDraft, error) {
	if err := validateDraft0218(d); err != nil {
		return d, err
	}
	r.draftMu.Lock()
	defer r.draftMu.Unlock()
	old, ok := r.releaseDrafts[d.ID]
	if !ok {
		return d, ErrNotFound
	}
	if old.Revision != d.Revision || old.ProjectID != d.ProjectID || old.OwnerID != d.OwnerID {
		return d, ErrConflict
	}
	d.CreatedAt = old.CreatedAt
	d.Revision++
	d.UpdatedAt = time.Now().UTC()
	r.releaseDrafts[d.ID] = d
	return d, nil
}
func (r *MemoryRepository) DeleteReleaseDraft(_ context.Context, id, ownerID string) error {
	r.draftMu.Lock()
	defer r.draftMu.Unlock()
	old, ok := r.releaseDrafts[id]
	if !ok || old.OwnerID != ownerID {
		return ErrNotFound
	}
	delete(r.releaseDrafts, id)
	return nil
}

const draftFields0218 = "id, project_id, owner_id, profile_id, channel, version, minecraft_version, loader, package_id, job_id, step, revision, created_at, updated_at"

func scanDraft0218(row interface{ Scan(...any) error }) (ReleaseDraft, error) {
	var d ReleaseDraft
	err := row.Scan(&d.ID, &d.ProjectID, &d.OwnerID, &d.ProfileID, &d.Channel, &d.Version, &d.MinecraftVersion, &d.Loader, &d.PackageID, &d.JobID, &d.Step, &d.Revision, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ReleaseDraft{}, ErrNotFound
	}
	return d, err
}
func (r *SQLRepository) CreateReleaseDraft(ctx context.Context, d ReleaseDraft) (ReleaseDraft, error) {
	if err := r.check(); err != nil {
		return d, err
	}
	if err := validateDraft0218(d); err != nil {
		return d, err
	}
	return scanDraft0218(r.db.QueryRowContext(ctx, `INSERT INTO release_drafts_0218(id,project_id,owner_id,profile_id,channel,version,minecraft_version,loader,package_id,job_id,step) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+draftFields0218, d.ID, d.ProjectID, d.OwnerID, d.ProfileID, d.Channel, d.Version, d.MinecraftVersion, d.Loader, d.PackageID, d.JobID, d.Step))
}
func (r *SQLRepository) ListReleaseDrafts(ctx context.Context, projectID, ownerID string) ([]ReleaseDraft, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+draftFields0218+` FROM release_drafts_0218 WHERE project_id=$1 AND owner_id=$2 ORDER BY updated_at DESC LIMIT 100`, projectID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReleaseDraft{}
	for rows.Next() {
		d, e := scanDraft0218(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (r *SQLRepository) GetReleaseDraft(ctx context.Context, id string) (ReleaseDraft, error) {
	if err := r.check(); err != nil {
		return ReleaseDraft{}, err
	}
	return scanDraft0218(r.db.QueryRowContext(ctx, `SELECT `+draftFields0218+` FROM release_drafts_0218 WHERE id=$1`, id))
}
func (r *SQLRepository) UpdateReleaseDraft(ctx context.Context, d ReleaseDraft) (ReleaseDraft, error) {
	if err := r.check(); err != nil {
		return d, err
	}
	if err := validateDraft0218(d); err != nil {
		return d, err
	}
	next, err := scanDraft0218(r.db.QueryRowContext(ctx, `UPDATE release_drafts_0218 SET profile_id=$4,channel=$5,version=$6,minecraft_version=$7,loader=$8,package_id=$9,job_id=$10,step=$11,revision=revision+1,updated_at=now() WHERE id=$1 AND project_id=$2 AND owner_id=$3 AND revision=$12 RETURNING `+draftFields0218, d.ID, d.ProjectID, d.OwnerID, d.ProfileID, d.Channel, d.Version, d.MinecraftVersion, d.Loader, d.PackageID, d.JobID, d.Step, d.Revision))
	if errors.Is(err, ErrNotFound) {
		return d, ErrConflict
	}
	return next, err
}
func (r *SQLRepository) DeleteReleaseDraft(ctx context.Context, id, ownerID string) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM release_drafts_0218 WHERE id=$1 AND owner_id=$2`, id, ownerID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

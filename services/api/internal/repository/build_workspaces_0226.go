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

// BuildFile identifies immutable, content-addressed uploaded bytes. Path is a
// logical path inside the game, never a filesystem path on the API host.
type BuildFile struct {
	Path       string   `json:"path"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	Ownership  string   `json:"ownership"`
	Executable bool     `json:"executable"`
	TargetOS   []string `json:"targetOs,omitempty"`
	Selected   bool     `json:"selected"`
}

type BuildSettings struct {
	Minecraft    model.MinecraftInfo `json:"minecraft"`
	Runtime      model.RuntimeInfo   `json:"runtime"`
	Directories  model.Directories   `json:"directories,omitempty"`
	FileRules    []model.FileRule    `json:"fileRules,omitempty"`
	ToolVersions map[string]string   `json:"toolVersions,omitempty"`
}

type BuildWorkspace struct {
	ID              string        `json:"id"`
	ProjectID       string        `json:"projectId"`
	OwnerID         string        `json:"ownerId"`
	ProfileID       string        `json:"profileId"`
	Channel         string        `json:"channel"`
	Version         string        `json:"version"`
	ProfileRevision int64         `json:"profileRevision"`
	ProfileDigest   string        `json:"profileDigest"`
	Settings        BuildSettings `json:"settings"`
	Files           []BuildFile   `json:"files"`
	State           string        `json:"state"`
	BuildDigest     string        `json:"buildDigest,omitempty"`
	PackageID       string        `json:"packageId,omitempty"`
	Revision        int64         `json:"revision"`
	CreatedAt       time.Time     `json:"createdAt"`
	UpdatedAt       time.Time     `json:"updatedAt"`
}

type BuildWorkspaceStore interface {
	CreateBuildWorkspace(context.Context, BuildWorkspace) (BuildWorkspace, error)
	GetBuildWorkspace(context.Context, string) (BuildWorkspace, error)
	ListBuildWorkspaces(context.Context, string, string) ([]BuildWorkspace, error)
	SaveBuildWorkspace(context.Context, BuildWorkspace) (BuildWorkspace, error)
}

func validWorkspace0226(w BuildWorkspace) error {
	for _, id := range []string{w.ID, w.ProjectID, w.OwnerID, w.ProfileID, w.Channel, w.Version} {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n") {
			return errors.New("invalid workspace identity")
		}
	}
	if w.ProfileRevision < 1 || len(w.ProfileDigest) != 64 || len(w.Files) > 25000 {
		return errors.New("invalid pinned profile or file count")
	}
	return nil
}
func cloneWorkspace0226(w BuildWorkspace) BuildWorkspace {
	// JSON roundtrip produces fully independent nested slices/maps; no caller can
	// mutate a persisted record without passing through revision-checked save.
	b, _ := json.Marshal(w)
	var c BuildWorkspace
	_ = json.Unmarshal(b, &c)
	return c
}
func (r *MemoryRepository) CreateBuildWorkspace(_ context.Context, w BuildWorkspace) (BuildWorkspace, error) {
	if err := validWorkspace0226(w); err != nil {
		return w, err
	}
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	if r.buildWorkspaces == nil {
		r.buildWorkspaces = make(map[string]BuildWorkspace)
	}
	if _, exists := r.buildWorkspaces[w.ID]; exists {
		return w, ErrConflict
	}
	now := time.Now().UTC()
	w.Revision = 1
	w.State = "importing"
	w.CreatedAt = now
	w.UpdatedAt = now
	r.buildWorkspaces[w.ID] = cloneWorkspace0226(w)
	return cloneWorkspace0226(w), nil
}
func (r *MemoryRepository) GetBuildWorkspace(_ context.Context, id string) (BuildWorkspace, error) {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	w, ok := r.buildWorkspaces[id]
	if !ok {
		return w, ErrNotFound
	}
	return cloneWorkspace0226(w), nil
}
func (r *MemoryRepository) ListBuildWorkspaces(_ context.Context, projectID, ownerID string) ([]BuildWorkspace, error) {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	rows := []BuildWorkspace{}
	for _, w := range r.buildWorkspaces {
		if w.ProjectID == projectID && w.OwnerID == ownerID {
			rows = append(rows, cloneWorkspace0226(w))
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UpdatedAt.After(rows[j].UpdatedAt) })
	return rows, nil
}
func (r *MemoryRepository) SaveBuildWorkspace(_ context.Context, w BuildWorkspace) (BuildWorkspace, error) {
	if err := validWorkspace0226(w); err != nil {
		return w, err
	}
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	old, ok := r.buildWorkspaces[w.ID]
	if !ok {
		return w, ErrNotFound
	}
	if old.Revision != w.Revision || old.ProjectID != w.ProjectID || old.OwnerID != w.OwnerID || old.ProfileID != w.ProfileID || old.Channel != w.Channel || old.Version != w.Version || old.ProfileDigest != w.ProfileDigest || old.ProfileRevision != w.ProfileRevision || old.Settings.Minecraft.Version != w.Settings.Minecraft.Version {
		return w, ErrConflict
	}
	if old.State == "built" {
		return w, ErrImmutable
	}
	w.Revision++
	w.CreatedAt = old.CreatedAt
	w.UpdatedAt = time.Now().UTC()
	r.buildWorkspaces[w.ID] = cloneWorkspace0226(w)
	return cloneWorkspace0226(w), nil
}
func (r *SQLRepository) CreateBuildWorkspace(ctx context.Context, w BuildWorkspace) (BuildWorkspace, error) {
	if err := r.check(); err != nil {
		return w, err
	}
	if err := validWorkspace0226(w); err != nil {
		return w, err
	}
	now := time.Now().UTC()
	w.Revision = 1
	w.State = "importing"
	w.CreatedAt = now
	w.UpdatedAt = now
	b, err := json.Marshal(w)
	if err != nil {
		return w, err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO build_workspaces_0226(id,project_id,owner_id,revision,data) VALUES($1,$2,$3,1,$4::jsonb) ON CONFLICT DO NOTHING`, w.ID, w.ProjectID, w.OwnerID, string(b))
	if err != nil {
		return w, err
	}
	// Ensures duplicate requests do not report success for existing IDs.
	got, err := r.GetBuildWorkspace(ctx, w.ID)
	if err != nil {
		return w, err
	}
	if got.CreatedAt != w.CreatedAt || got.OwnerID != w.OwnerID {
		return w, ErrConflict
	}
	return got, nil
}
func decodeWorkspace0226(row interface{ Scan(...any) error }) (BuildWorkspace, error) {
	var raw []byte
	var w BuildWorkspace
	err := row.Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	if err != nil {
		return w, err
	}
	err = json.Unmarshal(raw, &w)
	return w, err
}
func (r *SQLRepository) GetBuildWorkspace(ctx context.Context, id string) (BuildWorkspace, error) {
	if err := r.check(); err != nil {
		return BuildWorkspace{}, err
	}
	return decodeWorkspace0226(r.db.QueryRowContext(ctx, `SELECT data FROM build_workspaces_0226 WHERE id=$1`, id))
}
func (r *SQLRepository) ListBuildWorkspaces(ctx context.Context, projectID, ownerID string) ([]BuildWorkspace, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT data FROM build_workspaces_0226 WHERE project_id=$1 AND owner_id=$2 ORDER BY updated_at DESC LIMIT 100`, projectID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BuildWorkspace{}
	for rows.Next() {
		w, e := decodeWorkspace0226(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, w)
	}
	return items, rows.Err()
}
func (r *SQLRepository) SaveBuildWorkspace(ctx context.Context, w BuildWorkspace) (BuildWorkspace, error) {
	if err := r.check(); err != nil {
		return w, err
	}
	if err := validWorkspace0226(w); err != nil {
		return w, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return w, err
	}
	defer tx.Rollback()
	old, err := decodeWorkspace0226(tx.QueryRowContext(ctx, `SELECT data FROM build_workspaces_0226 WHERE id=$1 FOR UPDATE`, w.ID))
	if err != nil {
		return w, err
	}
	if old.Revision != w.Revision || old.OwnerID != w.OwnerID || old.ProjectID != w.ProjectID || old.ProfileID != w.ProfileID || old.Channel != w.Channel || old.Version != w.Version || old.ProfileDigest != w.ProfileDigest || old.ProfileRevision != w.ProfileRevision || old.Settings.Minecraft.Version != w.Settings.Minecraft.Version {
		return w, ErrConflict
	}
	if old.State == "built" {
		return w, ErrImmutable
	}
	w.Revision++
	w.CreatedAt = old.CreatedAt
	w.UpdatedAt = time.Now().UTC()
	b, e := json.Marshal(w)
	if e != nil {
		return w, e
	}
	res, e := tx.ExecContext(ctx, `UPDATE build_workspaces_0226 SET revision=$2,data=$3::jsonb,updated_at=now() WHERE id=$1 AND revision=$4`, w.ID, w.Revision, string(b), old.Revision)
	if e != nil {
		return w, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return w, e
	}
	if n != 1 {
		return w, fmt.Errorf("%w: revision mismatch", ErrConflict)
	}
	return w, tx.Commit()
}

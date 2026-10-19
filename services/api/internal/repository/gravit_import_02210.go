package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// GravitImportWriter02210 persists the newly converted profile AND its initial
// pinned workspace as one unit. No source secrets/permissions are copied.
type GravitImportWriter02210 interface {
	CreateGravitProfileWorkspace02210(context.Context, model.Profile, BuildWorkspace) (model.Profile, BuildWorkspace, error)
}

func prepareGravitImport02210(p model.Profile, w BuildWorkspace) (model.Profile, BuildWorkspace, error) {
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.IsDefault = false
	var err error
	if p.Revision != 0 {
		return p, w, errors.New("new Gravit import cannot carry source revision")
	}
	p, err = model.NormalizeProfileV2(p)
	if err != nil {
		return p, w, err
	}
	if w.ProjectID != p.ProjectID || w.ProfileID != p.ID {
		return p, w, errors.New("workspace scope does not match profile")
	}
	w.ProfileRevision = 1
	w.ProfileDigest = p.Digest
	if err = validWorkspace0226(w); err != nil {
		return p, w, err
	}
	if w.Settings.Minecraft.Loader != p.Loader || w.Settings.Minecraft.Version == "" {
		return p, w, errors.New("invalid workspace Minecraft loader/version")
	}
	return p, w, nil
}

func (r *MemoryRepository) CreateGravitProfileWorkspace02210(ctx context.Context, p model.Profile, w BuildWorkspace) (model.Profile, BuildWorkspace, error) {
	if _, err := r.GetProject(p.ProjectID); err != nil {
		return p, w, err
	}
	p, w, err := prepareGravitImport02210(p, w)
	if err != nil {
		return p, w, err
	}
	r.profileMu.Lock()
	defer r.profileMu.Unlock()
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	for _, existing := range r.profiles {
		if existing.ProjectID == p.ProjectID && existing.ID == p.ID {
			return p, w, ErrConflict
		}
	}
	if _, exists := r.buildWorkspaces[w.ID]; exists {
		return p, w, ErrConflict
	}
	now := time.Now().UTC()
	p.Revision, p.CreatedAt, p.UpdatedAt = 1, now, now
	w.Revision, w.State, w.CreatedAt, w.UpdatedAt = 1, "importing", now, now
	if r.profileHistory == nil {
		r.profileHistory = map[string][]model.ProfileSnapshot{}
	}
	if r.buildWorkspaces == nil {
		r.buildWorkspaces = map[string]BuildWorkspace{}
	}
	r.profiles = append(r.profiles, p)
	r.profileHistory[p.ProjectID+"\x00"+p.ID] = []model.ProfileSnapshot{model.SnapshotProfile(p)}
	r.buildWorkspaces[w.ID] = cloneWorkspace0226(w)
	return p, cloneWorkspace0226(w), nil
}

func (r *SQLRepository) CreateGravitProfileWorkspace02210(ctx context.Context, p model.Profile, w BuildWorkspace) (model.Profile, BuildWorkspace, error) {
	if err := r.check(); err != nil {
		return p, w, err
	}
	p, w, err := prepareGravitImport02210(p, w)
	if err != nil {
		return p, w, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return p, w, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `INSERT INTO profiles(id,project_id,name,description,loader,preset,is_default,created_at,updated_at,schema_version,revision,digest)
 VALUES($1,$2,$3,$4,$5,$6,false,$7,$7,'2.0',1,$8) ON CONFLICT (project_id,id) DO NOTHING`, p.ID, p.ProjectID, p.Name, p.Description, p.Loader, p.Preset, now, p.Digest)
	if err != nil {
		return p, w, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return p, w, err
	}
	if n != 1 {
		return p, w, ErrConflict
	}
	p.Revision, p.CreatedAt, p.UpdatedAt = 1, now, now
	snap := model.SnapshotProfile(p)
	raw, err := json.Marshal(snap.Spec)
	if err != nil {
		return p, w, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO profile_revisions_0221(project_id,profile_id,revision,schema_version,digest,spec,created_at) VALUES($1,$2,1,'2.0',$3,$4::jsonb,$5)`, p.ProjectID, p.ID, snap.Digest, string(raw), now); err != nil {
		return p, w, fmt.Errorf("persist imported profile snapshot: %w", err)
	}
	w.Revision, w.State, w.CreatedAt, w.UpdatedAt = 1, "importing", now, now
	data, err := json.Marshal(w)
	if err != nil {
		return p, w, err
	}
	res, err = tx.ExecContext(ctx, `INSERT INTO build_workspaces_0226(id,project_id,owner_id,revision,data) VALUES($1,$2,$3,1,$4::jsonb) ON CONFLICT DO NOTHING`, w.ID, w.ProjectID, w.OwnerID, string(data))
	if err != nil {
		return p, w, err
	}
	n, err = res.RowsAffected()
	if err != nil {
		return p, w, err
	}
	if n != 1 {
		return p, w, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return p, w, err
	}
	return p, w, nil
}

package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"strings"
	"time"
)

// CreateProfileExclusive0225 is the required storage primitive for clone/import
// and presets. Existing identities MUST be rejected, even with matching content.
func (r *MemoryRepository) CreateProfileExclusive0225(p model.Profile) (model.Profile, error) {
	if _, err := r.GetProject(p.ProjectID); err != nil {
		return model.Profile{}, err
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	var err error
	if p, err = model.NormalizeProfileV2(p); err != nil {
		return model.Profile{}, err
	}
	if p.Revision != 0 {
		return model.Profile{}, errors.New("new profile must not supply a revision")
	}
	r.profileMu.Lock()
	defer r.profileMu.Unlock()
	for _, existing := range r.profiles {
		if existing.ProjectID == p.ProjectID && existing.ID == p.ID {
			return model.Profile{}, ErrConflict
		}
	}
	now := time.Now().UTC()
	p.Revision, p.CreatedAt, p.UpdatedAt = 1, now, now
	if r.profileHistory == nil {
		r.profileHistory = make(map[string][]model.ProfileSnapshot)
	}
	r.profiles = append(r.profiles, p)
	r.profileHistory[p.ProjectID+"\x00"+p.ID] = []model.ProfileSnapshot{model.SnapshotProfile(p)}
	return p, nil
}

func (r *SQLRepository) CreateProfileExclusive0225(p model.Profile) (model.Profile, error) {
	if err := r.check(); err != nil {
		return model.Profile{}, err
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	var err error
	if p, err = model.NormalizeProfileV2(p); err != nil {
		return model.Profile{}, err
	}
	if p.Revision != 0 {
		return model.Profile{}, errors.New("new profile must not supply a revision")
	}
	tx, err := r.db.Begin()
	if err != nil {
		return model.Profile{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	res, err := tx.Exec(`INSERT INTO profiles(id,project_id,name,description,loader,preset,is_default,created_at,updated_at,schema_version,revision,digest,minecraft_version,loader_version,java_major)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,'2.0',1,$9,$10,$11,$12) ON CONFLICT (project_id,id) DO NOTHING`,
		p.ID, p.ProjectID, p.Name, p.Description, p.Loader, p.Preset, p.IsDefault, now, p.Digest, p.MinecraftVersion, p.LoaderVersion, p.JavaMajor)
	if err != nil {
		return model.Profile{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return model.Profile{}, err
	}
	if n != 1 {
		return model.Profile{}, ErrConflict
	}
	p.Revision, p.CreatedAt, p.UpdatedAt = 1, now, now
	shot := model.SnapshotProfile(p)
	raw, err := json.Marshal(shot.Spec)
	if err != nil {
		return model.Profile{}, err
	}
	if _, err := tx.Exec(`INSERT INTO profile_revisions_0221(project_id,profile_id,revision,schema_version,digest,spec,created_at)
        VALUES($1,$2,1,'2.0',$3,$4::jsonb,$5)`, p.ProjectID, p.ID, shot.Digest, string(raw), now); err != nil {
		return model.Profile{}, fmt.Errorf("persist profile revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.Profile{}, err
	}
	return p, nil
}

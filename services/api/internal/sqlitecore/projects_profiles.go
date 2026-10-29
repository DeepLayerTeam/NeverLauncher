package sqlitecore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

func nowNS() int64 { return time.Now().UTC().UnixNano() }
func ts(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
func ns(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}

func scanProject(s interface{ Scan(...any) error }) (model.Project, error) {
	var p model.Project
	var created, updated int64
	err := s.Scan(&p.ID, &p.Name, &p.Description, &p.Homepage, &p.Repository, &p.DefaultChannel, &created, &updated)
	p.CreatedAt, p.UpdatedAt = ts(created), ts(updated)
	return p, err
}

const projectFields = "id,name,description,homepage,repository,default_channel,created_at,updated_at"

func (r *Repository) GetProject(ctx context.Context, id string) (p model.Project, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var e error
		p, e = scanProject(q.QueryRowContext(ctx, "SELECT "+projectFields+" FROM projects WHERE id=?", id))
		return notFound(e)
	})
	return
}
func (r *Repository) ListProjects(ctx context.Context) (out []model.Project, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, "SELECT "+projectFields+" FROM projects ORDER BY id")
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			p, e := scanProject(rows)
			if e != nil {
				return e
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return
}
func (r *Repository) SaveProject(ctx context.Context, p model.Project, actor string) (model.Project, error) {
	if strings.TrimSpace(actor) == "" {
		return model.Project{}, errors.New("project mutation requires audit actor")
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	if p.ID == "" {
		p.ID = strings.ToLower(strings.ReplaceAll(p.Name, " ", "-"))
	}
	if p.ID == "" || p.Name == "" || strings.ContainsRune(p.ID, '\x00') {
		return p, errors.New("project id/name required and NUL prohibited")
	}
	if p.DefaultChannel == "" {
		p.DefaultChannel = "stable"
	}
	err := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := nowNS()
		created := now
		e := q.QueryRowContext(ctx, "SELECT created_at FROM projects WHERE id=?", p.ID).Scan(&created)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO projects(id,name,description,homepage,repository,default_channel,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)
 ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,homepage=excluded.homepage,repository=excluded.repository,default_channel=excluded.default_channel,updated_at=excluded.updated_at`, p.ID, p.Name, p.Description, p.Homepage, p.Repository, p.DefaultChannel, created, now)
		if e != nil {
			return conflict(e)
		}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "project:save", Target: p.ID})
	})
	if err != nil {
		return model.Project{}, err
	}
	return r.GetProject(ctx, p.ID)
}

const profileFields = "id,project_id,name,description,loader,preset,is_default,minecraft_version,loader_version,java_major,created_at,updated_at,revision,digest"

func scanProfile(s interface{ Scan(...any) error }) (model.Profile, error) {
	var p model.Profile
	var created, updated int64
	err := s.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Loader, &p.Preset, &p.IsDefault, &p.MinecraftVersion, &p.LoaderVersion, &p.JavaMajor, &created, &updated, &p.Revision, &p.Digest)
	if err != nil {
		return p, err
	}
	p.CreatedAt, p.UpdatedAt = ts(created), ts(updated)
	p.SchemaVersion = model.ProfileSchemaV2
	if p.Revision < 1 || p.Digest != model.ProfileDigest(model.ProfileSpecOf(p)) {
		return model.Profile{}, fmt.Errorf("inconsistent profile digest or revision %s/%s", p.ProjectID, p.ID)
	}
	return p, nil
}
func (r *Repository) ListProfiles(ctx context.Context, projectID string) (out []model.Profile, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, "SELECT "+profileFields+" FROM profiles WHERE project_id=? ORDER BY id", projectID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			p, e := scanProfile(rows)
			if e != nil {
				return e
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return
}
func (r *Repository) GetProfile(ctx context.Context, projectID, profileID string) (p model.Profile, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var e error
		p, e = scanProfile(q.QueryRowContext(ctx, "SELECT "+profileFields+" FROM profiles WHERE project_id=? AND id=?", projectID, profileID))
		return notFound(e)
	})
	return
}

// SaveProfile performs first-writer insertion or revision-CAS update along
// with immutable history in a single BEGIN IMMEDIATE / FULL-sync COMMIT.
func (r *Repository) SaveProfile(ctx context.Context, p model.Profile, actor string) (actual model.Profile, err error) {
	if strings.TrimSpace(actor) == "" {
		return actual, errors.New("profile mutation requires audit actor")
	}
	p.Name = strings.TrimSpace(p.Name)
	p.ID = strings.TrimSpace(p.ID)
	if p.ID == "" {
		p.ID = strings.ToLower(strings.ReplaceAll(p.Name, " ", "-"))
	}
	p, err = model.NormalizeProfileV2(p)
	if err != nil {
		return actual, err
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var existing model.Profile
		existing, e := scanProfile(q.QueryRowContext(ctx, "SELECT "+profileFields+" FROM profiles WHERE project_id=? AND id=?", p.ProjectID, p.ID))
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		now := nowNS()
		if errors.Is(e, sql.ErrNoRows) {
			if p.Revision > 1 {
				return ErrConflict
			}
			p.Revision = 1
			p.CreatedAt = ts(now)
			p.UpdatedAt = ts(now)
			_, e = q.ExecContext(ctx, `INSERT INTO profiles(project_id,id,name,description,loader,preset,is_default,revision,digest,created_at,updated_at,minecraft_version,loader_version,java_major) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.ProjectID, p.ID, p.Name, p.Description, p.Loader, p.Preset, p.IsDefault, p.Revision, p.Digest, now, now, p.MinecraftVersion, p.LoaderVersion, p.JavaMajor)
			if e != nil {
				return conflict(e)
			}
			actual = p
		} else {
			if p.Revision != 0 && p.Revision != existing.Revision {
				return ErrConflict
			}
			if p.Digest == existing.Digest {
				actual = existing
				return nil
			}
			p.Revision = existing.Revision + 1
			p.CreatedAt = existing.CreatedAt
			p.UpdatedAt = ts(now)
			result, e := q.ExecContext(ctx, `UPDATE profiles SET name=?,description=?,loader=?,preset=?,is_default=?,revision=?,digest=?,updated_at=?,minecraft_version=?,loader_version=?,java_major=? WHERE project_id=? AND id=? AND revision=?`, p.Name, p.Description, p.Loader, p.Preset, p.IsDefault, p.Revision, p.Digest, now, p.MinecraftVersion, p.LoaderVersion, p.JavaMajor, p.ProjectID, p.ID, existing.Revision)
			if e != nil {
				return e
			}
			n, e := result.RowsAffected()
			if e != nil {
				return e
			}
			if n != 1 {
				return ErrConflict
			}
			actual = p
		}
		snapshot := model.SnapshotProfile(actual)
		raw, e := json.Marshal(snapshot.Spec)
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO profile_revisions(project_id,profile_id,revision,digest,schema_version,spec,created_at) VALUES(?,?,?,?,?,?,?)`, actual.ProjectID, actual.ID, actual.Revision, snapshot.Digest, snapshot.SchemaVersion, string(raw), now)
		if e != nil {
			return conflict(e)
		}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "profile:save", Target: actual.ProjectID + "/" + actual.ID})
	})
	return
}

func readSnapshot(s interface{ Scan(...any) error }, projectID, profileID string) (model.ProfileSnapshot, error) {
	var sn model.ProfileSnapshot
	var raw string
	if err := s.Scan(&sn.SchemaVersion, &sn.Revision, &sn.Digest, &raw); err != nil {
		return sn, notFound(err)
	}
	if err := json.Unmarshal([]byte(raw), &sn.Spec); err != nil {
		return sn, err
	}
	if err := model.ValidateProfileSnapshot(sn, projectID, profileID); err != nil {
		return sn, err
	}
	return sn, nil
}
func (r *Repository) CurrentProfileSnapshot(ctx context.Context, projectID, profileID string) (sn model.ProfileSnapshot, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var e error
		sn, e = readSnapshot(q.QueryRowContext(ctx, `SELECT h.schema_version,h.revision,h.digest,h.spec FROM profiles p JOIN profile_revisions h ON h.project_id=p.project_id AND h.profile_id=p.id AND h.revision=p.revision AND h.digest=p.digest WHERE p.project_id=? AND p.id=?`, projectID, profileID), projectID, profileID)
		return e
	})
	return
}
func (r *Repository) ListProfileRevisions(ctx context.Context, projectID, profileID string) (out []model.ProfileSnapshot, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT schema_version,revision,digest,spec FROM profile_revisions WHERE project_id=? AND profile_id=? ORDER BY revision`, projectID, profileID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			sn, e := readSnapshot(rows, projectID, profileID)
			if e != nil {
				return e
			}
			out = append(out, sn)
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if len(out) == 0 {
			return ErrNotFound
		}
		return nil
	})
	return
}

func (r *Repository) SaveChannel(ctx context.Context, c model.ReleaseChannel, actor string) (model.ReleaseChannel, error) {
	if strings.TrimSpace(actor) == "" {
		return c, errors.New("channel mutation requires audit actor")
	}
	c.ID = strings.TrimSpace(c.ID)
	c.Name = strings.TrimSpace(c.Name)
	if c.ID == "" {
		c.ID = strings.ToLower(strings.ReplaceAll(c.Name, " ", "-"))
	}
	if c.Name == "" {
		c.Name = c.ID
	}
	if c.ID == "" || c.ProjectID == "" {
		return c, errors.New("channel id/projectId required")
	}
	err := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `INSERT INTO channels(project_id,id,name,description,protected) VALUES(?,?,?,?,?) ON CONFLICT(project_id,id) DO UPDATE SET name=excluded.name,description=excluded.description,protected=excluded.protected`, c.ProjectID, c.ID, c.Name, c.Description, c.Protected)
		if e != nil {
			return conflict(e)
		}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "channel:save", Target: c.ProjectID + "/" + c.ID})
	})
	return c, err
}
func (r *Repository) ListChannels(ctx context.Context, projectID string) (out []model.ReleaseChannel, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT id,project_id,name,description,protected FROM channels WHERE project_id=? ORDER BY id`, projectID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c model.ReleaseChannel
			if e = rows.Scan(&c.ID, &c.ProjectID, &c.Name, &c.Description, &c.Protected); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return
}

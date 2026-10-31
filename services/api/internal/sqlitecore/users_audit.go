package sqlitecore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func uid() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (r *Repository) ListRoles(ctx context.Context) (out []model.Role, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT id,name,description,permissions FROM roles ORDER BY id`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var role model.Role
			var raw string
			if e = rows.Scan(&role.ID, &role.Name, &role.Description, &raw); e != nil {
				return e
			}
			if e = json.Unmarshal([]byte(raw), &role.Permissions); e != nil {
				return e
			}
			out = append(out, role)
		}
		return rows.Err()
	})
	return
}

const userFields = `id,email,display_name,role_id,status,password_hash,password_updated_at,last_login_at,disabled_at,created_at,updated_at`

func scanUser(s interface{ Scan(...any) error }) (model.User, error) {
	var u model.User
	var pw, login, disabled, created, updated int64
	e := s.Scan(&u.ID, &u.Email, &u.DisplayName, &u.RoleID, &u.Status, &u.PasswordHash, &pw, &login, &disabled, &created, &updated)
	if e != nil {
		return u, e
	}
	u.PasswordUpdatedAt, u.LastLoginAt, u.DisabledAt, u.CreatedAt, u.UpdatedAt = ts(pw), ts(login), ts(disabled), ts(created), ts(updated)
	u.ProjectRoles = map[string]string{}
	return u, nil
}
func loadRoles(ctx context.Context, q sqlitedurable.Executor, u *model.User) error {
	rows, e := q.QueryContext(ctx, `SELECT project_id,role_id FROM project_user_roles WHERE user_id=? ORDER BY project_id`, u.ID)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var project, role string
		if e = rows.Scan(&project, &role); e != nil {
			return e
		}
		u.ProjectRoles[project] = role
	}
	return rows.Err()
}
func (r *Repository) GetUser(ctx context.Context, id string) (u model.User, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var e error
		u, e = scanUser(q.QueryRowContext(ctx, "SELECT "+userFields+" FROM users WHERE id=?", id))
		if e != nil {
			return notFound(e)
		}
		return loadRoles(ctx, q, &u)
	})
	return
}
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (u model.User, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var e error
		u, e = scanUser(q.QueryRowContext(ctx, "SELECT "+userFields+" FROM users WHERE email=? COLLATE NOCASE", email))
		if e != nil {
			return notFound(e)
		}
		return loadRoles(ctx, q, &u)
	})
	return
}
func (r *Repository) ListUsers(ctx context.Context) (out []model.User, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, "SELECT "+userFields+" FROM users ORDER BY email")
		if e != nil {
			return e
		}
		for rows.Next() {
			u, e := scanUser(rows)
			if e != nil {
				_ = rows.Close()
				return e
			}
			out = append(out, u)
		}
		e = errors.Join(rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for i := range out {
			if e = loadRoles(ctx, q, &out[i]); e != nil {
				return e
			}
		}
		return nil
	})
	return
}

// AuthEpoch must be checked by DEP01 sessions when session parity is enabled.
// It monotonically increases on role, password, status, project binding edits.
func (r *Repository) AuthEpoch(ctx context.Context, userID string) (epoch int64, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return notFound(q.QueryRowContext(ctx, `SELECT auth_epoch FROM users WHERE id=?`, userID).Scan(&epoch))
	})
	return
}

// SaveUser never applies a partially committed role binding: user record,
// normalized per-project roles, generation bump and audit commit together.
// Actor is mandatory because user-management changes are security events.
func (r *Repository) SaveUser(ctx context.Context, u model.User, actor string) (model.User, error) {
	if strings.TrimSpace(actor) == "" {
		return model.User{}, errors.New("security actor required")
	}
	u.ID = strings.TrimSpace(u.ID)
	u.Email = strings.TrimSpace(strings.ToLower(u.Email))
	if u.ID == "" {
		id, e := uid()
		if e != nil {
			return model.User{}, e
		}
		u.ID = "user-" + id
	}
	if u.Email == "" || !strings.Contains(u.Email, "@") || strings.ContainsAny(u.Email, "\x00\r\n") {
		return model.User{}, errors.New("valid email required")
	}
	if u.RoleID == "" {
		u.RoleID = "viewer"
	}
	if u.Status == "" {
		u.Status = "active"
	}
	if u.Status != "active" && u.Status != "disabled" {
		return model.User{}, errors.New("invalid account status")
	}
	if u.ProjectRoles == nil {
		u.ProjectRoles = map[string]string{}
	}
	for project, role := range u.ProjectRoles {
		if project == "*" || strings.TrimSpace(project) == "" || strings.TrimSpace(role) == "" {
			return model.User{}, errors.New("invalid project role binding")
		}
	}
	err := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var prev model.User
		prev, e := scanUser(q.QueryRowContext(ctx, "SELECT "+userFields+" FROM users WHERE id=?", u.ID))
		newUser := errors.Is(e, sql.ErrNoRows)
		if e != nil && !newUser {
			return e
		}
		if !newUser {
			if e = loadRoles(ctx, q, &prev); e != nil {
				return e
			}
		}
		// New databases must bootstrap an active owner, not an implicit admin.
		if newUser {
			var count int
			if e = q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); e != nil {
				return e
			}
			if count == 0 && (u.RoleID != "owner" || u.Status != "active") {
				return errors.New("first user must be an active owner")
			}
		}
		now := nowNS()
		created := now
		if !newUser {
			created = ns(prev.CreatedAt)
		}
		pwDate := ns(u.PasswordUpdatedAt)
		if newUser && u.PasswordHash != "" && pwDate == 0 {
			pwDate = now
		}
		if !newUser && u.PasswordHash != prev.PasswordHash && pwDate == ns(prev.PasswordUpdatedAt) {
			pwDate = now
		}
		disabledDate := ns(u.DisabledAt)
		if u.Status == "disabled" && disabledDate == 0 {
			disabledDate = now
		}
		if u.Status == "active" {
			disabledDate = 0
		}
		changed := newUser || u.RoleID != prev.RoleID || u.Status != prev.Status || u.PasswordHash != prev.PasswordHash || !sameBindings(prev.ProjectRoles, u.ProjectRoles)
		_, e = q.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status,password_hash,password_updated_at,last_login_at,disabled_at,created_at,updated_at,auth_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
 ON CONFLICT(id) DO UPDATE SET email=excluded.email,display_name=excluded.display_name,role_id=excluded.role_id,status=excluded.status,password_hash=excluded.password_hash,password_updated_at=excluded.password_updated_at,last_login_at=excluded.last_login_at,disabled_at=excluded.disabled_at,updated_at=excluded.updated_at,auth_epoch=users.auth_epoch+?`, u.ID, u.Email, u.DisplayName, u.RoleID, u.Status, u.PasswordHash, pwDate, ns(u.LastLoginAt), disabledDate, created, now, boolInt(changed))
		if e != nil {
			return conflict(e)
		}
		if !newUser {
			for project, role := range prev.ProjectRoles {
				if u.ProjectRoles[project] != role {
					if _, e = q.ExecContext(ctx, `DELETE FROM project_user_roles WHERE user_id=? AND project_id=?`, u.ID, project); e != nil {
						return e
					}
				}
			}
		}
		// Canonical assignment inserts only changed rows.
		projects := make([]string, 0, len(u.ProjectRoles))
		for p := range u.ProjectRoles {
			projects = append(projects, p)
		}
		sort.Strings(projects)
		for _, project := range projects {
			role := u.ProjectRoles[project]
			if !newUser && prev.ProjectRoles[project] == role {
				continue
			}
			_, e = q.ExecContext(ctx, `INSERT INTO project_user_roles(user_id,project_id,role_id) VALUES(?,?,?) ON CONFLICT(user_id,project_id) DO UPDATE SET role_id=excluded.role_id`, u.ID, project, role)
			if e != nil {
				return conflict(e)
			}
		}
		action := "user:update"
		if newUser {
			action = "user:create"
		}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: action, Target: u.ID})
	})
	if err != nil {
		return model.User{}, err
	}
	return r.GetUser(ctx, u.ID)
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func sameBindings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// UpdatePassword and DisableUser are explicit security mutations and preserve
// all unrelated fields (including per-project bindings) without overwriting.
func (r *Repository) UpdatePassword(ctx context.Context, id, hash, actor string) error {
	if actor == "" || id == "" {
		return errors.New("actor/user required")
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		res, e := q.ExecContext(ctx, `UPDATE users SET password_hash=?,password_updated_at=?,updated_at=?,auth_epoch=auth_epoch+1 WHERE id=?`, hash, nowNS(), nowNS(), id)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrNotFound
		}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "user:password-change", Target: id})
	})
}
func (r *Repository) SetUserDisabled(ctx context.Context, id string, disabled bool, actor string) error {
	if actor == "" || id == "" {
		return errors.New("actor/user required")
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		state := "active"
		d := int64(0)
		if disabled {
			state = "disabled"
			d = nowNS()
		}
		now := nowNS()
		res, e := q.ExecContext(ctx, `UPDATE users SET status=?,disabled_at=?,updated_at=?,auth_epoch=auth_epoch+CASE WHEN status<>? THEN 1 ELSE 0 END WHERE id=?`, state, d, now, state, id)
		if e != nil {
			return conflict(e)
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrNotFound
		}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "user:status", Target: id})
	})
}

func recordAudit(ctx context.Context, q sqlitedurable.Executor, event model.AuditEvent) error {
	if event.ID == "" {
		id, e := uid()
		if e != nil {
			return e
		}
		event.ID = "audit-" + id
	}
	if strings.TrimSpace(event.Actor) == "" || strings.TrimSpace(event.Action) == "" {
		return errors.New("audit actor/action required")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = ts(nowNS())
	}
	_, e := q.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at,correlation_id,reason_code,job_id) VALUES(?,?,?,?,?,?,?,?,?,?)`, event.ID, event.Actor, event.Action, event.Target, event.IP, event.UserAgent, ns(event.CreatedAt), event.CorrelationID, event.ReasonCode, event.JobID)
	return conflict(e)
}
func (r *Repository) RecordAudit(ctx context.Context, event model.AuditEvent) error {
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error { return recordAudit(ctx, q, event) })
}
func (r *Repository) ListAudit(ctx context.Context, limit int) (out []model.AuditEvent, err error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT id,actor,action,target,ip,user_agent,created_at,correlation_id,reason_code,job_id FROM audit_events ORDER BY created_at DESC,id DESC LIMIT ?`, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a model.AuditEvent
			var created int64
			if e = rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.IP, &a.UserAgent, &created, &a.CorrelationID, &a.ReasonCode, &a.JobID); e != nil {
				return e
			}
			a.CreatedAt = ts(created)
			out = append(out, a)
		}
		return rows.Err()
	})
	return
}

// Count is an operational diagnostic: failed queries return an error rather
// than silently emitting an empty list as some legacy interfaces do.
func (r *Repository) Count(ctx context.Context) (map[string]int64, error) {
	names := []string{"projects", "profiles", "profile_revisions", "channels", "releases", "channel_heads", "users", "project_user_roles", "roles", "audit_events", "auth_sessions", "refresh_families", "refresh_tokens", "access_tokens", "mfa_totp", "mfa_recovery", "minecraft_profiles", "minecraft_sessions", "auth_revocation_events", "bridge_nodes", "bridge_nonces", "bridge_join_tickets", "durable_jobs", "durable_job_attempts", "durable_scope_leases", "durable_outbox", "bridge_runtime", "bridge_runtime_nonces", "bridge_commands", "package_blobs", "extension_publishers", "extension_packages", "extension_installs", "extension_install_history", "extension_kv", "extension_kv_history"}
	values := map[string]int64{}
	err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		for _, name := range names {
			var n int64
			if e := q.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", name)).Scan(&n); e != nil {
				return e
			}
			values[name] = n
		}
		return nil
	})
	return values, err
}

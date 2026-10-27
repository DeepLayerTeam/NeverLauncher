// Package sqlitecore provides transactional SQLite persistence for DEP01 core
// entities. It deliberately does not implement the whole Backend Repository:
// device attestation and coordinator state remain PostgreSQL-
// only until their durable SQLite implementations exist. No memory fallback.
package sqlitecore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

var (
	ErrNotFound  = errors.New("sqlite core: record not found")
	ErrConflict  = errors.New("sqlite core: revision or unique constraint conflict")
	ErrImmutable = errors.New("sqlite core: immutable published release or history")
)

const SchemaVersion = 326

type Repository struct{ store *sqlitedurable.Store }

func Open(ctx context.Context, options sqlitedurable.Options) (*Repository, error) {
	store, err := sqlitedurable.Open(ctx, options)
	if err != nil {
		return nil, err
	}
	repo := &Repository{store: store}
	if err = repo.ensureMigrationBackup(ctx, options.Path); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err = repo.migrate(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err = repo.Check(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return repo, nil
}

// OpenExisting never creates or migrates a core schema; for inspection and
// startup readiness checks. The caller must first ensure the DB file exists.
func OpenExisting(ctx context.Context, options sqlitedurable.Options) (*Repository, error) {
	store, err := sqlitedurable.Open(ctx, options)
	if err != nil {
		return nil, err
	}
	r := &Repository{store: store}
	if err = r.Check(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return r, nil
}

func (r *Repository) Close() error { return r.store.Close() }

// ensureMigrationBackup makes a verified, restorable snapshot mandatory before
// modifying any existing SQLite schema. New installations do not need a backup.
// A failed backup blocks the migration; there is no unsafe override.
func (r *Repository) ensureMigrationBackup(ctx context.Context, path string) error {
	var old int
	if err := r.store.Read(ctx, func(q sqlitedurable.Executor) error { return q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&old) }); err != nil {
		return err
	}
	if old == 0 || old == SchemaVersion {
		return nil
	}
	// Do not perform backups for unsupported/future versions or migrate them.
	if old != 322 && old != 323 && old != 324 && old != 325 {
		return fmt.Errorf("SQLite schema %d unsupported; refusing migration", old)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	backupDir := filepath.Join(filepath.Dir(abs), "pre-upgrade-backups")
	if err = os.Mkdir(backupDir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if st, e := os.Lstat(backupDir); e != nil {
		return e
	} else if !st.IsDir() || st.Mode().Perm() != 0700 || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe pre-upgrade backup directory")
	}
	name := fmt.Sprintf("%s-schema-%d-%d.db", filepath.Base(abs), old, time.Now().UTC().UnixNano())
	destination := filepath.Join(backupDir, name)
	if _, err = sqlitedurable.OnlineBackup(ctx, abs, destination); err != nil {
		return fmt.Errorf("mandatory pre-upgrade backup: %w", err)
	}
	if _, err = sqlitedurable.VerifyBackup(ctx, destination); err != nil {
		return fmt.Errorf("mandatory pre-upgrade backup validation: %w", err)
	}
	// Restore verification in a separate temporary path before allowing DDL.
	tmpDir, err := os.MkdirTemp(backupDir, ".restore-proof-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	restored := filepath.Join(tmpDir, "state.db")
	if _, err = sqlitedurable.RestoreBackup(ctx, destination, restored, false); err != nil {
		return fmt.Errorf("pre-upgrade restore proof failed: %w", err)
	}
	// Structural verification is performed during RestoreBackup. Older core
	// schemas need not pass new-version application-level checks yet.
	return nil
}

// Schema changes and built-in role seeding are committed atomically. An
// unrecognised schema version fails closed, including databases from the future.
func (r *Repository) migrate(ctx context.Context) error {
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var version int
		if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version != 0 && version != 322 && version != 323 && version != 324 && version != 325 && version != SchemaVersion {
			return fmt.Errorf("sqlite core schema %d incompatible with %d", version, SchemaVersion)
		}
		if version == 0 {
			for _, stmt := range ddl {
				if _, err := q.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("sqlite core schema: %w", err)
				}
			}
			for _, role := range builtInRoles {
				if _, err := q.ExecContext(ctx, `INSERT INTO roles(id,name,description,permissions) VALUES(?,?,?,?)`, role.id, role.name, role.desc, role.perms); err != nil {
					return err
				}
			}
		}
		if version == 0 || version == 322 {
			for _, stmt := range authDDL {
				if _, err := q.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("sqlite auth migration 323: %w", err)
				}
			}
		}
		if version != 324 && version != 325 && version != SchemaVersion {
			for _, stmt := range joinDDL {
				if _, err := q.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("sqlite replay/join migration 324: %w", err)
				}
			}
		}
		if version != 325 && version != SchemaVersion {
			for _, stmt := range durableDDL {
				if _, err := q.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("sqlite durable migration 325: %w", err)
				}
			}
		}
		if version != SchemaVersion {
			for _, stmt := range fullStateDDL {
				if _, err := q.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("sqlite full durable migration 326: %w", err)
				}
			}
			if _, err := q.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", SchemaVersion)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Check verifies actual persisted data, not just the DB handle. It detects
// corrupted profile history, dangling channel pointers, invalid roles and
// broken manifest digest references prior to exposing the repository.
func (r *Repository) Check(ctx context.Context) error {
	return r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var v int
		if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
			return err
		}
		if v != SchemaVersion {
			return fmt.Errorf("sqlite core: unexpected schema %d", v)
		}
		var integrity string
		if err := q.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
			return err
		}
		if integrity != "ok" {
			return fmt.Errorf("sqlite core integrity: %s", integrity)
		}
		var fk string
		rows, err := q.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return err
		}
		if rows.Next() {
			var a, b, c, d any
			if er := rows.Scan(&a, &b, &c, &d); er == nil {
				fk = fmt.Sprint(a, ":", b, ":", c, ":", d)
			} else {
				fk = er.Error()
			}
		}
		err = errors.Join(err, rows.Err(), rows.Close())
		if err != nil {
			return err
		}
		if fk != "" {
			return fmt.Errorf("sqlite foreign_key_check: %s", fk)
		}
		checks := []string{
			`SELECT COUNT(*) FROM profiles p LEFT JOIN profile_revisions h ON h.project_id=p.project_id AND h.profile_id=p.id AND h.revision=p.revision AND h.digest=p.digest WHERE h.profile_id IS NULL`,
			`SELECT COUNT(*) FROM channel_heads h LEFT JOIN releases r ON r.id=h.release_id AND r.status='published' AND r.project_id=h.project_id AND r.profile_id=h.profile_id AND r.channel=h.channel WHERE r.id IS NULL`,
			`SELECT COUNT(*) FROM users u LEFT JOIN roles r ON r.id=u.role_id WHERE r.id IS NULL`,
			`SELECT COUNT(*) FROM project_user_roles pur LEFT JOIN roles r ON r.id=pur.role_id WHERE r.id IS NULL`,
			`SELECT COUNT(*) FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id JOIN auth_sessions s ON s.id=f.session_id WHERE f.status='active' AND s.status<>'active' AND t.status='current'`,
			`SELECT COUNT(*) FROM minecraft_sessions m JOIN auth_sessions s ON s.id=m.never_session_id WHERE m.status='active' AND s.status<>'active'`,
			`SELECT COUNT(*) FROM bridge_join_tickets t JOIN bridge_nodes n ON n.id=t.node_id WHERE t.status='active' AND (n.status<>'active' OR t.issued_identity_epoch<>n.identity_epoch OR t.issued_fingerprint<>n.fingerprint)`,
			`SELECT COUNT(*) FROM bridge_join_tickets WHERE status='consumed' AND consumed_at=0`,
			`SELECT COUNT(*) FROM bridge_nodes WHERE length(public_key)<>32`,
			`SELECT COUNT(*) FROM durable_jobs j WHERE j.status='running' AND NOT EXISTS (SELECT 1 FROM durable_job_attempts a WHERE a.job_id=j.id AND a.attempt=j.attempt_count AND a.status='running' AND a.lease_fence=j.lease_fence)`,
			`SELECT COUNT(*) FROM durable_job_attempts a WHERE a.status='running' AND NOT EXISTS (SELECT 1 FROM durable_jobs j WHERE j.id=a.job_id AND j.status='running' AND j.attempt_count=a.attempt AND j.lease_fence=a.lease_fence)`,
		}
		for _, stmt := range checks {
			var n int
			if err := q.QueryRowContext(ctx, stmt).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				return fmt.Errorf("sqlite core inconsistent records (%d): %s", n, stmt)
			}
		}
		// Detect wrong immutable profile payloads and tampered channel heads
		// even when SQLite pages and foreign keys are structurally valid.
		profiles, e := q.QueryContext(ctx, "SELECT "+"id,project_id,name,description,loader,preset,is_default,created_at,updated_at,revision,digest"+" FROM profiles")
		if e != nil {
			return e
		}
		for profiles.Next() {
			if _, e = scanProfile(profiles); e != nil {
				_ = profiles.Close()
				return e
			}
		}
		e = errors.Join(profiles.Err(), profiles.Close())
		if e != nil {
			return e
		}
		heads, e := q.QueryContext(ctx, `SELECT r.manifest,h.manifest_digest FROM channel_heads h JOIN releases r ON r.id=h.release_id`)
		if e != nil {
			return e
		}
		for heads.Next() {
			var raw, digest string
			if e = heads.Scan(&raw, &digest); e != nil {
				_ = heads.Close()
				return e
			}
			sum := sha256.Sum256([]byte(raw))
			if hex.EncodeToString(sum[:]) != digest {
				_ = heads.Close()
				return errors.New("sqlite core channel manifest digest mismatch")
			}
		}
		if e = errors.Join(heads.Err(), heads.Close()); e != nil {
			return e
		}
		// Detect payload tampering not visible to PRAGMA integrity_check.
		for _, table := range []string{"durable_jobs", "durable_outbox"} {
			items, er := q.QueryContext(ctx, "SELECT payload,payload_digest FROM "+table)
			if er != nil {
				return er
			}
			for items.Next() {
				var payload, stored string
				if er = items.Scan(&payload, &stored); er != nil {
					break
				}
				actual := sha256.Sum256([]byte(payload))
				if hex.EncodeToString(actual[:]) != stored {
					er = fmt.Errorf("sqlite durable %s payload digest mismatch", table)
					break
				}
			}
			er = errors.Join(er, items.Err(), items.Close())
			if er != nil {
				return er
			}
		}
		return r.checkFullState(ctx, q)
	})
}

func (r *Repository) Checkpoint(ctx context.Context) (sqlitedurable.WALStatus, error) {
	return r.store.Checkpoint(ctx)
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
func conflict(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "constraint failed") || strings.Contains(err.Error(), "UNIQUE constraint") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

type roleSeed struct{ id, name, desc, perms string }

var builtInRoles = []roleSeed{
	{"owner", "Владелец", "Полный доступ", `["*"]`},
	{"admin", "Администратор", "Администрирование платформы", `["project:read","project:write","release:prepare","release:publish","file:write","users:manage","roles:manage","audit:read","diagnostics:read","storage:manage","settings:manage","security:read","extension:manage","serverbridge:control","serverbridge:console","gameserver:broadcast","gameserver:moderate","gameserver:save","gameserver:traffic","gameserver:shutdown","gameserver:console"]`},
	{"release-manager", "Release Manager", "Управление релизами", `["project:read","release:prepare","release:publish","audit:read"]`},
	{"operator", "Оператор", "Управление сборками", `["project:read","project:write","release:prepare","file:write","diagnostics:read","serverbridge:control","gameserver:broadcast","gameserver:moderate","gameserver:save","gameserver:traffic"]`},
	{"support", "Поддержка", "Диагностика", `["project:read","diagnostics:read","audit:read"]`},
	{"developer", "Разработчик", "Подготовка релизов", `["project:read","release:prepare","file:write"]`},
	{"viewer", "Наблюдатель", "Чтение", `["project:read"]`},
	{"player", "Игрок", "Desktop", `["launcher:login","profile:download","profile:launch"]`},
}

var ddl = []string{
	`CREATE TABLE projects (id TEXT PRIMARY KEY NOT NULL CHECK(length(id)>0), name TEXT NOT NULL CHECK(length(name)>0), description TEXT NOT NULL DEFAULT '', homepage TEXT NOT NULL DEFAULT '', repository TEXT NOT NULL DEFAULT '', default_channel TEXT NOT NULL DEFAULT 'stable', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
	`CREATE TABLE profiles (project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT, id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', loader TEXT NOT NULL, preset TEXT NOT NULL DEFAULT '', is_default INTEGER NOT NULL CHECK(is_default IN(0,1)), revision INTEGER NOT NULL CHECK(revision>=1), digest TEXT NOT NULL CHECK(length(digest)=64), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(project_id,id)) WITHOUT ROWID`,
	`CREATE TABLE profile_revisions (project_id TEXT NOT NULL, profile_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=1), digest TEXT NOT NULL, schema_version TEXT NOT NULL CHECK(schema_version='2.0'), spec TEXT NOT NULL CHECK(json_valid(spec)), created_at INTEGER NOT NULL, PRIMARY KEY(project_id,profile_id,revision), FOREIGN KEY(project_id,profile_id) REFERENCES profiles(project_id,id) ON DELETE RESTRICT) WITHOUT ROWID`,
	`CREATE TRIGGER profile_revisions_no_update BEFORE UPDATE ON profile_revisions BEGIN SELECT RAISE(ABORT,'immutable profile history'); END`,
	`CREATE TRIGGER profile_revisions_no_delete BEFORE DELETE ON profile_revisions BEGIN SELECT RAISE(ABORT,'immutable profile history'); END`,
	`CREATE TABLE channels (project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT, id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', protected INTEGER NOT NULL CHECK(protected IN (0,1)), PRIMARY KEY(project_id,id)) WITHOUT ROWID`,
	`CREATE TABLE releases (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, profile_id TEXT NOT NULL, channel TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','published','archived')), manifest TEXT NOT NULL CHECK(json_valid(manifest)), published_at INTEGER NOT NULL DEFAULT 0, UNIQUE(project_id,profile_id,channel,version), FOREIGN KEY(project_id,profile_id) REFERENCES profiles(project_id,id) ON DELETE RESTRICT, FOREIGN KEY(project_id,channel) REFERENCES channels(project_id,id) ON DELETE RESTRICT)`,
	`CREATE TRIGGER published_release_immutable BEFORE UPDATE ON releases WHEN OLD.status='published' AND (NEW.manifest<>OLD.manifest OR NEW.status<>OLD.status OR NEW.published_at<>OLD.published_at OR NEW.project_id<>OLD.project_id OR NEW.profile_id<>OLD.profile_id OR NEW.channel<>OLD.channel OR NEW.version<>OLD.version) BEGIN SELECT RAISE(ABORT,'published release immutable'); END`,
	`CREATE TRIGGER releases_no_delete BEFORE DELETE ON releases WHEN OLD.status='published' BEGIN SELECT RAISE(ABORT,'published release immutable'); END`,
	`CREATE TABLE channel_heads(project_id TEXT NOT NULL,profile_id TEXT NOT NULL,channel TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE RESTRICT,version TEXT NOT NULL,manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64),updated_at INTEGER NOT NULL,PRIMARY KEY(project_id,profile_id,channel),FOREIGN KEY(project_id,profile_id) REFERENCES profiles(project_id,id) ON DELETE RESTRICT,FOREIGN KEY(project_id,channel) REFERENCES channels(project_id,id) ON DELETE RESTRICT) WITHOUT ROWID`,
	`CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', permissions TEXT NOT NULL CHECK(json_valid(permissions)))`,
	`CREATE TRIGGER roles_no_update BEFORE UPDATE ON roles BEGIN SELECT RAISE(ABORT,'immutable built-in role'); END`,
	`CREATE TRIGGER roles_no_delete BEFORE DELETE ON roles BEGIN SELECT RAISE(ABORT,'immutable built-in role'); END`,
	`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE UNIQUE, display_name TEXT NOT NULL DEFAULT '', role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT, status TEXT NOT NULL CHECK(status IN ('active','disabled')), password_hash TEXT NOT NULL DEFAULT '', password_updated_at INTEGER NOT NULL DEFAULT 0, last_login_at INTEGER NOT NULL DEFAULT 0, disabled_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK(auth_epoch>=1))`,
	`CREATE TABLE project_user_roles(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,PRIMARY KEY(user_id,project_id)) WITHOUT ROWID`,
	`CREATE TRIGGER users_no_last_owner_update AFTER UPDATE OF role_id,status ON users WHEN OLD.role_id='owner' AND OLD.status='active' BEGIN SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE role_id='owner' AND status='active')=0 THEN RAISE(ABORT,'cannot disable last active owner') END; END`,
	`CREATE TRIGGER users_no_last_owner_delete BEFORE DELETE ON users WHEN OLD.role_id='owner' AND OLD.status='active' AND (SELECT COUNT(*) FROM users WHERE role_id='owner' AND status='active')=1 BEGIN SELECT RAISE(ABORT,'cannot delete last owner'); END`,
	`CREATE TABLE audit_events(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,ip TEXT NOT NULL DEFAULT '',user_agent TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,correlation_id TEXT NOT NULL DEFAULT '',reason_code TEXT NOT NULL DEFAULT '',job_id TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX audit_events_time ON audit_events(created_at DESC,id DESC)`,
	`CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'immutable audit event'); END`,
	`CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'immutable audit event'); END`,
}

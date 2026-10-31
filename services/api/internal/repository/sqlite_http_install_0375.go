package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

const sqliteInstallationDDL0375 = `CREATE TABLE IF NOT EXISTS http_installation_0375 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 token_hash TEXT NOT NULL,
 token_used_at INTEGER,
 completed_at INTEGER,
 CHECK(completed_at IS NULL OR token_used_at IS NOT NULL)
)`

func minimalTokenDigest0375(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// InitializeMinimalInstallation0375 stores the bootstrap verifier before the
// listener starts. An existing verifier cannot be replaced by reconfiguring env.
func (r *SQLiteHTTPRepository0372) InitializeMinimalInstallation0375(ctx context.Context, token string, require bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	token = strings.TrimSpace(token)
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if _, e := q.ExecContext(ctx, sqliteInstallationDDL0375); e != nil {
			return e
		}
		if _, e := q.ExecContext(ctx, `INSERT OR IGNORE INTO http_installation_0375(singleton,token_hash) VALUES(1,'')`); e != nil {
			return e
		}
		var hash string
		var used, complete sql.NullInt64
		if e := q.QueryRowContext(ctx, `SELECT token_hash,token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&hash, &used, &complete); e != nil {
			return e
		}
		if hash == "" && !used.Valid && !complete.Valid {
			if len(r.mem.users) > 0 {
				return errors.New("SQLite already contains users without installation state; manual recovery required")
			}
			if token == "" {
				if require {
					return errors.New("fresh SQLite production install requires bootstrap token")
				}
				return nil
			}
			if len(token) < 32 {
				return errors.New("bootstrap token must have at least 32 characters")
			}
			_, e := q.ExecContext(ctx, `UPDATE http_installation_0375 SET token_hash=? WHERE singleton=1 AND token_hash=''`, minimalTokenDigest0375(token))
			return e
		}
		if !used.Valid && !complete.Valid && token != "" && subtle.ConstantTimeCompare([]byte(hash), []byte(minimalTokenDigest0375(token))) != 1 {
			return errors.New("bootstrap token differs from initialized installation")
		}
		return nil
	})
}

func (r *SQLiteHTTPRepository0372) MinimalInstallationStatus0375(ctx context.Context) (string, bool, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return "", false, false, r.failed
	}
	var hash string
	var used, completed sql.NullInt64
	err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT token_hash,token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&hash, &used, &completed)
	})
	return hash, used.Valid, completed.Valid, err
}

// BootstrapMinimalAdmin0375 couples token use, owner+identity, audit and HTTP
// domain snapshot in exactly one WAL transaction. No other request may observe
// the owner before the commit. An unknown commit outcome poisons the repository.
func (r *SQLiteHTTPRepository0372) BootstrapMinimalAdmin0375(ctx context.Context, user model.User, identity model.AuthIdentity, token, actor string) (model.User, error) {
	r.mu.Lock()
	start := len(r.mem.audit)
	defer r.unlockAndPublishAudit0372(start)
	if r.failed != nil {
		return model.User{}, r.failed
	}
	if len(r.mem.users) != 0 {
		return model.User{}, errors.New("first administrator already exists")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return model.User{}, errors.New("bootstrap token required")
	}
	// Verify the token before mutating the cache. Recheck under the WRITE
	// transaction to prevent a future separate consumer from racing us.
	var stored string
	var used, completed sql.NullInt64
	if err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT token_hash,token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&stored, &used, &completed)
	}); err != nil {
		return model.User{}, err
	}
	if stored == "" || used.Valid || completed.Valid || subtle.ConstantTimeCompare([]byte(stored), []byte(minimalTokenDigest0375(token))) != 1 {
		return model.User{}, errors.New("invalid or consumed bootstrap token")
	}
	created, err := r.mem.SaveUser(user)
	if err != nil {
		return model.User{}, err
	}
	identity.UserID = created.ID
	if _, err = r.mem.SaveAuthIdentity(identity); err != nil {
		r.failed = err
		return model.User{}, err
	}
	now := time.Now().UTC()
	r.mem.audit = append(r.mem.audit, model.AuditEvent{ID: fmt.Sprintf("install-admin-%d", now.UnixNano()), Actor: actor, Action: "install.bootstrap-admin", Target: created.Email, UserAgent: "0.37.5", CreatedAt: now})
	raw, err := json.Marshal(snapshotSQLiteHTTP0372(r.mem))
	if err != nil {
		r.failed = err
		return model.User{}, err
	}
	sum := sha256.Sum256(raw)
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		result, e := q.ExecContext(ctx, `UPDATE http_installation_0375 SET token_used_at=? WHERE singleton=1 AND token_hash=? AND token_used_at IS NULL AND completed_at IS NULL`, now.Unix(), stored)
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
		result, e = q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET sequence=sequence+1,sha256=?,document=? WHERE singleton=1 AND sequence=?`, hex.EncodeToString(sum[:]), raw, r.seq)
		if e != nil {
			return e
		}
		n, e = result.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		r.failed = fmt.Errorf("atomic bootstrap commit: %w", err)
		return model.User{}, r.failed
	}
	r.seq++
	return created, nil
}

func (r *SQLiteHTTPRepository0372) CompleteMinimalInstallation0375(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	if len(r.mem.users) == 0 || len(r.mem.projects) == 0 {
		return errors.New("installation requires an administrator and project")
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var used, completed sql.NullInt64
		if e := q.QueryRowContext(ctx, `SELECT token_used_at,completed_at FROM http_installation_0375 WHERE singleton=1`).Scan(&used, &completed); e != nil {
			return e
		}
		if completed.Valid {
			return nil
		}
		if !used.Valid {
			return errors.New("bootstrap administrator must be created before completion")
		}
		res, e := q.ExecContext(ctx, `UPDATE http_installation_0375 SET completed_at=?,token_hash='' WHERE singleton=1 AND token_used_at IS NOT NULL AND completed_at IS NULL`, time.Now().UTC().Unix())
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrConflict
		}
		return nil
	})
}

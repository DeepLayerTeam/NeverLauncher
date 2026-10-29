package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

// SQLiteHTTPRepository0372 persists the complete HTTP repository domain state
// in a single-process, FULL-sync WAL SQLite database. The in-process domain
// model is a cache, never a durable source: a mutation returns only after the
// new state and its integrity digest commit atomically. This design is intended
// for a small, single-node installation, not network HA or large data sets.
//
// Security-critical stable publication remains denied until an equivalent
// attestation/permit store is completed; it cannot be enabled by configuration.
// The deployment single-node gate remains closed until related auth stores,
// coordination, and installation are independently verified.
type SQLiteHTTPRepository0372 struct {
	mu        sync.Mutex
	store     *sqlitedurable.Store
	mem       *MemoryRepository
	seq       int64
	failed    error
	auditSink func(model.AuditEvent)
}

var _ Repository = (*SQLiteHTTPRepository0372)(nil)

const sqliteHTTPDDL0372 = `CREATE TABLE IF NOT EXISTS http_repository_state_0372 (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    state_version INTEGER NOT NULL CHECK(state_version=1),
    sequence INTEGER NOT NULL CHECK(sequence>=1),
    sha256 TEXT NOT NULL,
    document BLOB NOT NULL
)`

// OpenSQLiteHTTPRepository0372 owns the database and rejects another process
// attempting to acquire the same SQLite file. It never falls back to memory.
func OpenSQLiteHTTPRepository0372(ctx context.Context, path, publicURL string) (_ *SQLiteHTTPRepository0372, err error) {
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	r := &SQLiteHTTPRepository0372{store: store, mem: NewMemoryRepository(publicURL)}
	// Never seed the HTTP production repository with the development demo,
	// default admin credentials, or a pre-published synthetic release.
	r.mem.projects = nil
	r.mem.profiles = nil
	r.mem.channels = nil
	r.mem.releases = nil
	r.mem.files = nil
	r.mem.users = nil
	r.mem.identities = nil
	r.mem.audit = nil
	r.mem.channelHeads = make(map[string]model.ChannelHead)
	r.mem.validationPolicies = make(map[string]model.ProjectValidationPolicy)
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, sqliteHTTPDDL0372)
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, sqliteRuntimeDDL0373)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("sqlite HTTP schema: %w", err)
	}
	var raw []byte
	var sha string
	var ver int
	err = store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT state_version,sequence,sha256,document FROM http_repository_state_0372 WHERE singleton=1`).Scan(&ver, &r.seq, &sha, &raw)
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		err = r.persist(ctx)
		if err != nil {
			return nil, fmt.Errorf("create sqlite HTTP state: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("read sqlite HTTP state: %w", err)
	case ver != 1:
		return nil, fmt.Errorf("unsupported SQLite HTTP state format %d", ver)
	default:
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != sha {
			return nil, errors.New("SQLite HTTP state integrity digest mismatch")
		}
		var state sqliteHTTPState0372
		if err = json.Unmarshal(raw, &state); err != nil {
			return nil, fmt.Errorf("corrupt SQLite HTTP state: %w", err)
		}
		if !validPrivateSQLite0373(state) {
			return nil, errors.New("invalid SQLite private state alignment")
		}
		restoreSQLiteHTTP0372(r.mem, state)
	}
	return r, nil
}

// persist is called with the repository operation lock held, except during
// initial Open. A commit error makes the instance unusable to prevent the
// uncommitted in-process cache from ever being served as durable state.
func (r *SQLiteHTTPRepository0372) persist(ctx context.Context) error {
	raw, err := json.Marshal(snapshotSQLiteHTTP0372(r.mem))
	if err != nil {
		return fmt.Errorf("serialize SQLite HTTP state: %w", err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if r.seq == 0 {
			_, e := q.ExecContext(ctx, `INSERT INTO http_repository_state_0372(singleton,state_version,sequence,sha256,document) VALUES (1,1,1,?,?)`, digest, raw)
			return e
		}
		result, e := q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET sequence=sequence+1,sha256=?,document=? WHERE singleton=1 AND sequence=? AND state_version=1`, digest, raw, r.seq)
		if e != nil {
			return e
		}
		changed, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if changed != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("commit SQLite HTTP state: %w", err)
	}
	r.seq++
	return nil
}

func (r *SQLiteHTTPRepository0372) Health(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	return r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var result string
		if err := q.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
			return err
		}
		if result != "ok" {
			return fmt.Errorf("sqlite HTTP quick_check: %s", result)
		}
		var seq int64
		if err := q.QueryRowContext(ctx, `SELECT sequence FROM http_repository_state_0372 WHERE singleton=1`).Scan(&seq); err != nil {
			return err
		}
		if seq != r.seq {
			return ErrConflict
		}
		return nil
	})
}

func (r *SQLiteHTTPRepository0372) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	err := r.store.Close()
	r.failed = sqlitedurable.ErrClosed
	return err
}

// The last active owner cannot be removed through normal account operations.
func sqliteHTTPOtherActiveOwner0372(users []model.User, exceptID string) bool {
	for _, u := range users {
		if u.ID != exceptID && u.RoleID == "owner" && u.Status == "active" {
			return true
		}
	}
	return false
}

// Audit hooks run only after a successful durable commit and after releasing
// the state lock, so event-bus callbacks may safely call this repository.
func (r *SQLiteHTTPRepository0372) unlockAndPublishAudit0372(start int) {
	var emitted []model.AuditEvent
	sink := r.auditSink
	if r.failed == nil && sink != nil && start < len(r.mem.audit) {
		emitted = append([]model.AuditEvent(nil), r.mem.audit[start:]...)
	}
	r.mu.Unlock()
	if sink != nil {
		for _, event := range emitted {
			sink(event)
		}
	}
}

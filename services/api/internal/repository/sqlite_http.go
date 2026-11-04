package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// SQLiteHTTPRepository0372 persists the complete HTTP repository domain state
// in a single-process, FULL-sync WAL SQLite database. The in-process domain
// model is a cache, a durable source: a mutation returns only after the
// new state and its integrity digest commit atomically. This design is intended
// for a small, single-node installation, not network HA or large data sets.
//
// Stable publication uses SQLite-bound, signed attestation verification and
// one-use transactional permits (0.37.4), while the 0.37.5 minimal deployment accepts one local Linux instance;
// online backup and bidirectional migration remain separate milestones.
type SQLiteHTTPRepository0372 struct {
	mu        sync.Mutex
	store     *sqlitedurable.Store
	mem       *MemoryRepository
	seq       int64
	digest    string
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
// attempting to acquire the same SQLite file. It falls back to memory.
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
	// Seed the HTTP production repository with the development demo,
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
	// Never initialize an unrelated/nonempty SQLite database as a fresh
	// installation. A missing snapshot in an existing database is corruption,
	// not permission to wipe the project silently.
	existing := false
	err = store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if e = rows.Scan(&name); e != nil {
				return e
			}
			if name != "http_repository_state_0372" { // other tables need the state table as an owner
				existing = true
				continue
			}
			existing = true
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if !existing {
			return nil
		}
		var found int
		if e = q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='http_repository_state_0372'`).Scan(&found); e != nil {
			return e
		}
		if found != 1 {
			return errors.New("SQLite HTTP state table missing from existing database")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sqlite HTTP preflight: %w", err)
	}
	legacy, upgraded, e := preflightHTTPUpgrade0472(ctx, store, existing)
	if e != nil {
		return nil, fmt.Errorf("sqlite HTTP compatibility preflight: %w", e)
	}
	if legacy {
		if _, e = sqlitedurable.PreUpgradeBackup0472(ctx, path, "http-v1-upgrade"); e != nil {
			return nil, e
		}
		if e = migrateHTTPSnapshot0472(ctx, store, upgraded); e != nil {
			return nil, fmt.Errorf("sqlite HTTP upgrade: %w", e)
		}
	}
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, sqliteHTTPDDL0372)
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, sqliteRuntimeDDL0373)
		if e != nil {
			return e
		}
		for _, stmt := range strings.Split(sqliteStablePermitDDL0374, ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, e = q.ExecContext(ctx, stmt); e != nil {
				return e
			}
		}
		return nil
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
		if existing {
			return nil, errors.New("SQLite HTTP snapshot missing from existing database; refusing to initialize empty state")
		}
		err = r.persist(ctx)
		if err != nil {
			return nil, fmt.Errorf("create sqlite HTTP state: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("read sqlite HTTP state: %w", err)
	case ver != 1:
		return nil, fmt.Errorf("unsupported SQLite HTTP state format %d", ver)
	case r.seq < 1:
		return nil, errors.New("invalid SQLite HTTP sequence")
	default:
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != sha {
			return nil, errors.New("SQLite HTTP state integrity digest mismatch")
		}
		state, e := decodeSQLiteHTTPDocument0471(raw)
		if e != nil {
			return nil, fmt.Errorf("corrupt SQLite HTTP state: %w", e)
		}
		r.digest = sha
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
	r.digest = digest
	return nil
}

// decodeSQLiteHTTPDocument0471 validates the stored envelope without losing
// unknown or missing fields. encoding/json.Unmarshal alone accepts both, so a
// JSON document from an incompatible version could otherwise load as empty
// collections while still carrying a valid document checksum.
func decodeSQLiteHTTPDocument0471(raw []byte) (sqliteHTTPState0372, error) {
	var state sqliteHTTPState0372
	expected := make(map[string]struct{})
	typ := reflect.TypeOf(state)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			return state, fmt.Errorf("unversioned SQLite snapshot field %s", field.Name)
		}
		expected[name] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	tok, err := decoder.Token()
	if err != nil {
		return state, err
	}
	if tok != json.Delim('{') {
		return state, errors.New("SQLite HTTP snapshot must be an object")
	}
	seen := make(map[string]struct{}, len(expected))
	for decoder.More() {
		tok, err = decoder.Token()
		if err != nil {
			return state, err
		}
		name, ok := tok.(string)
		if !ok {
			return state, errors.New("SQLite HTTP snapshot property is not a string")
		}
		if _, ok = expected[name]; !ok {
			return state, fmt.Errorf("unknown SQLite HTTP snapshot field %q", name)
		}
		if _, ok = seen[name]; ok {
			return state, fmt.Errorf("duplicate SQLite HTTP snapshot field %q", name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return state, err
		}
		if name == "private0373" {
			if err = validateSQLitePrivateFields0471(value); err != nil {
				return state, err
			}
		}
	}
	if _, err = decoder.Token(); err != nil {
		return state, err
	}
	if len(seen) != len(expected) {
		return state, fmt.Errorf("SQLite HTTP snapshot missing fields (%d/%d)", len(seen), len(expected))
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return state, errors.New("trailing SQLite HTTP snapshot values")
		}
		return state, err
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if !validPrivateSQLite0373(state) {
		return state, errors.New("SQLite HTTP private state alignment mismatch")
	}
	return state, nil
}

// Private arrays hold password verifiers, refresh tokens and device keys.
// Missing/duplicate fields must not be silently interpreted as empty secrets.
func validateSQLitePrivateFields0471(raw []byte) error {
	expected := make(map[string]struct{})
	typ := reflect.TypeOf(sqliteHTTPPrivate0373{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		expected[name] = struct{}{}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("SQLite HTTP private state must be an object")
	}
	seen := map[string]struct{}{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("SQLite HTTP private property is not a string")
		}
		if _, ok = expected[key]; !ok {
			return fmt.Errorf("unknown SQLite HTTP private property %q", key)
		}
		if _, ok = seen[key]; ok {
			return fmt.Errorf("duplicate SQLite HTTP private property %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("SQLite HTTP private snapshot missing properties (%d/%d)", len(seen), len(expected))
	}
	var trailing any
	if err = d.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing SQLite HTTP private state")
		}
		return err
	}
	return nil
}

func (r *SQLiteHTTPRepository0372) Health(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var result string
		if e := q.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); e != nil {
			return e
		}
		if result != "ok" {
			return fmt.Errorf("sqlite HTTP quick_check: %s", result)
		}
		var seq int64
		var sha string
		var raw []byte
		if e := q.QueryRowContext(ctx, `SELECT sequence,sha256,document FROM http_repository_state_0372 WHERE singleton=1`).Scan(&seq, &sha, &raw); e != nil {
			return e
		}
		if seq != r.seq || sha != r.digest {
			return ErrConflict
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != sha {
			return errors.New("SQLite HTTP state digest mismatch")
		}
		if _, e := decodeSQLiteHTTPDocument0471(raw); e != nil {
			return fmt.Errorf("SQLite HTTP state invalid: %w", e)
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		r.failed = err
	}
	return err
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

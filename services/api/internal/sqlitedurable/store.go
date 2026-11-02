// Package sqlitedurable implements the DEP00 SQLite/WAL transactional store.
// It is NOT the application's SQLite Repository (DEP01), and must not be selected
// as the backend's repository before the schema/auth/coordination parity gates.
package sqlitedurable

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	DriverVersion      = "v1.61.0"
	EngineVersion      = "3.54.1"
	DefaultBusyTimeout = 5000
	DefaultReaders     = 4
)

var (
	ErrClosed        = errors.New("sqlite storage closed")
	ErrCommitUnknown = errors.New("sqlite durable commit returned an error; outcome must be reconciled before replay")
	ErrPoisoned      = errors.New("sqlite transaction state uncertain; close store and reconcile with a fresh connection before serving requests")
)

// Options requires a plain absolute or relative on-disk pathname, a URI,
// in-memory DB, special file, or shared writable network/overlay volume.
type Options struct {
	Path        string
	BusyTimeout time.Duration // 0 = 5s; positive values must be between 1ms and 60s
	Readers     int           // 0 = 4; maximum 16
}

// Store is a single-process, exclusive-owner SQLite WAL store. A separate
// process cannot open the same DB via Open while this store holds its lock.
// All writes serialize on the one writer connection. Reads use a bounded pool.
type Store struct {
	path     string
	writer   *sql.DB
	readers  *sql.DB
	lock     *os.File
	mu       sync.RWMutex
	closed   bool
	poisoned atomic.Bool
}

type WALStatus struct {
	Busy               int `json:"busy"`
	LogFrames          int `json:"logFrames"`
	CheckpointedFrames int `json:"checkpointedFrames"`
}

func Open(ctx context.Context, opt Options) (_ *Store, err error) {
	if strings.TrimSpace(opt.Path) == "" || strings.ContainsAny(opt.Path, "\x00?\n") || strings.HasPrefix(strings.ToLower(opt.Path), "file:") || strings.HasPrefix(opt.Path, ":") {
		return nil, fmt.Errorf("sqlite requires a local filesystem path (no URI/in-memory DB)")
	}
	path, err := filepath.Abs(opt.Path)
	if err != nil {
		return nil, err
	}
	if opt.BusyTimeout == 0 {
		opt.BusyTimeout = 5 * time.Second
	}
	if opt.BusyTimeout < time.Millisecond || opt.BusyTimeout > 60*time.Second {
		return nil, fmt.Errorf("busy timeout must be in [1ms,60s]")
	}
	if opt.Readers == 0 {
		opt.Readers = DefaultReaders
	}
	if opt.Readers < 1 || opt.Readers > 16 {
		return nil, fmt.Errorf("readers must be 1..16")
	}
	if err = verifyLocalPath(path); err != nil {
		return nil, err
	}
	lock, err := exclusiveLock(path + ".owner.lock")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = releaseLock(lock)
		}
	}()
	if err = durableFileSystemProbe(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("sqlite durable filesystem probe failed: %w", err)
	}
	if err = checkSQLiteSidecars(path); err != nil {
		return nil, err
	}
	if err = createDatabase0600(path); err != nil {
		return nil, err
	}
	base := (&url.URL{Scheme: "file", Path: path}).String()
	// modernc.org/sqlite applies every _pragma on *each newly opened* connection.
	// Do not set safety PRAGMAs once on a pooled sql.DB and assume persistence.
	timeout := strconv.FormatInt(opt.BusyTimeout.Milliseconds(), 10)
	writerDSN := base + "?mode=rwc&_pragma=foreign_keys(1)&_pragma=busy_timeout(" + timeout + ")&_pragma=synchronous(FULL)&_pragma=journal_mode(WAL)&_pragma=trusted_schema(OFF)&_pragma=secure_delete(ON)"
	readerDSN := base + "?mode=ro&_pragma=foreign_keys(1)&_pragma=busy_timeout(" + timeout + ")&_pragma=trusted_schema(OFF)&_pragma=query_only(ON)"
	s := &Store{path: path, lock: lock}
	defer func() {
		if err != nil {
			if s.readers != nil {
				_ = s.readers.Close()
			}
			if s.writer != nil {
				_ = s.writer.Close()
			}
		}
	}()
	s.writer, err = sql.Open("sqlite", writerDSN)
	if err != nil {
		return nil, err
	}
	s.writer.SetMaxOpenConns(1)
	s.writer.SetMaxIdleConns(1)
	s.writer.SetConnMaxLifetime(0)
	if err = s.writer.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("sqlite writer opening: %w", err)
	}
	if err = checkExistingRegularFile(path); err != nil {
		return nil, err
	}
	if err = s.verifyWriter(ctx, timeout); err != nil {
		return nil, err
	}
	s.readers, err = sql.Open("sqlite", readerDSN)
	if err != nil {
		return nil, err
	}
	s.readers.SetMaxOpenConns(opt.Readers)
	s.readers.SetMaxIdleConns(opt.Readers)
	s.readers.SetConnMaxLifetime(0)
	if err = s.readers.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("sqlite reader opening: %w", err)
	}
	if err = s.verifyReaders(ctx, timeout); err != nil {
		return nil, err
	}
	if err = checkSQLiteSidecars(path); err != nil {
		return nil, err
	}
	return s, nil
}

// Create the database with 0600 instead of SQLite's permissive default 0644.
// The database's parent directory was verified before acquiring owner lock.
func createDatabase0600(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return checkExistingRegularFile(path)
	}
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = errors.Join(dir.Sync(), dir.Close())
	return err
}

func checkExistingRegularFile(path string) error {
	f, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sqlite database must be a regular file")
	}
	if f.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("sqlite database %s has unsafe permissions %04o; require 0600", path, f.Mode().Perm())
	}
	return nil
}

// SQLite may create WAL and shared-memory sidecars before the first query.
// Never allow symlinked or world-readable sidecars in a private datastore.
func checkSQLiteSidecars(path string) error {
	for _, name := range []string{path + "-wal", path + "-shm"} {
		info, err := os.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("unsafe SQLite sidecar %q (expected regular private file)", name)
		}
	}
	return nil
}

// Verify every SQLite integrity result (not just the first row), including
// foreign keys. A quick_check alone cannot certify a recovered WAL database.
func verifyDatabaseIntegrity(ctx context.Context, q Executor) error {
	rows, err := q.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return err
	}
	var result string
	if !rows.Next() {
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		return errors.New("SQLite integrity_check returned no rows")
	}
	if err = rows.Scan(&result); err != nil {
		_ = rows.Close()
		return err
	}
	if result != "ok" {
		_ = rows.Close()
		return fmt.Errorf("SQLite integrity_check: %s", result)
	}
	if rows.Next() {
		_ = rows.Close()
		return errors.New("SQLite integrity_check produced unexpected additional rows")
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	hasViolation := rows.Next()
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if hasViolation {
		return errors.New("SQLite foreign_key_check found inconsistent records")
	}
	return nil
}

func pragmaInt(ctx context.Context, conn *sql.Conn, name string, want int) error {
	var value int
	if err := conn.QueryRowContext(ctx, "PRAGMA "+name).Scan(&value); err != nil {
		return err
	}
	if value != want {
		return fmt.Errorf("unsafe sqlite PRAGMA %s=%d; expected %d", name, value, want)
	}
	return nil
}

func checkEngine(ctx context.Context, conn *sql.Conn) error {
	var got string
	if err := conn.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&got); err != nil {
		return err
	}
	if got != EngineVersion {
		return fmt.Errorf("sqlite engine %q is unsupported (pinned %s, driver %s)", got, EngineVersion, DriverVersion)
	}
	var sourceID string
	if err := conn.QueryRowContext(ctx, "SELECT sqlite_source_id()").Scan(&sourceID); err != nil {
		return err
	}
	if !strings.Contains(sourceID, "555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76") {
		return fmt.Errorf("unsupported SQLite source revision: %s", sourceID)
	}
	opts, err := conn.QueryContext(ctx, "PRAGMA compile_options")
	if err != nil {
		return err
	}
	defer opts.Close()
	threadsafe := false
	for opts.Next() {
		var v string
		if err = opts.Scan(&v); err != nil {
			return err
		}
		if v == "THREADSAFE=1" || v == "THREADSAFE=2" {
			threadsafe = true
		}
		if strings.HasPrefix(v, "OMIT_WAL") || v == "OMIT_FOREIGN_KEY" {
			return fmt.Errorf("sqlite compiled without mandatory feature: %s", v)
		}
	}
	if err = opts.Err(); err != nil {
		return err
	}
	if !threadsafe {
		return errors.New("sqlite THREADSAFE compile option not confirmed")
	}
	return nil
}

func (s *Store) verifyWriter(ctx context.Context, timeout string) error {
	conn, err := s.writer.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = checkEngine(ctx, conn); err != nil {
		return err
	}
	var journal string
	if err = conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return err
	}
	if !strings.EqualFold(journal, "wal") {
		return fmt.Errorf("SQLite WAL mandatory; got %s", journal)
	}
	for k, v := range map[string]int{"foreign_keys": 1, "synchronous": 2, "trusted_schema": 0, "secure_delete": 1} {
		if err = pragmaInt(ctx, conn, k, v); err != nil {
			return err
		}
	}
	n, _ := strconv.Atoi(timeout)
	if err = pragmaInt(ctx, conn, "busy_timeout", n); err != nil {
		return err
	}
	if err = verifyDatabaseIntegrity(ctx, conn); err != nil {
		return fmt.Errorf("sqlite open integrity failure: %w", err)
	}
	return nil
}

func (s *Store) verifyReaders(ctx context.Context, timeout string) error {
	conn, err := s.readers.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = checkEngine(ctx, conn); err != nil {
		return err
	}
	for k, v := range map[string]int{"foreign_keys": 1, "query_only": 1, "trusted_schema": 0} {
		if err = pragmaInt(ctx, conn, k, v); err != nil {
			return err
		}
	}
	n, _ := strconv.Atoi(timeout)
	return pragmaInt(ctx, conn, "busy_timeout", n)
}

// Executor exposes connection-bound statements while the immediate transaction
// is active. Callers must run raw BEGIN/COMMIT/ROLLBACK/PRAGMA here.
type Executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Write uses BEGIN IMMEDIATE (not database/sql BeginTx's deferred BEGIN).
// A successful return requires SQLite to report a successful FULL-sync COMMIT.
// On error it rolls back with an independent timeout, even if ctx was canceled.
func (s *Store) Write(ctx context.Context, fn func(Executor) error) (err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if s.poisoned.Load() {
		return ErrPoisoned
	}
	if fn == nil {
		return errors.New("nil sqlite write callback")
	}
	conn, err := s.writer.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("sqlite BEGIN IMMEDIATE: %w", err)
	}
	active := true
	defer func() {
		// Always try to roll back using an independent context, including after
		// cancellation and panic. An unresolved live transaction must never be
		// returned to the pooled writer connection.
		if active {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, rbErr := conn.ExecContext(rollbackCtx, "ROLLBACK")
			cancel()
			if rbErr != nil {
				// database/sql may already have discarded a canceled connection;
				// otherwise invalidate the connection and fail this store closed.
				if !errors.Is(rbErr, sql.ErrConnDone) && !errors.Is(rbErr, driver.ErrBadConn) {
					s.poisoned.Store(true)
					err = errors.Join(err, fmt.Errorf("sqlite rollback unresolved: %w", rbErr))
				}
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
		if p := recover(); p != nil {
			panic(p)
		}
	}()
	if err = fn(conn); err != nil {
		return err
	}
	// SQLite commits even if an API call races with a deadline; callers must
	// reconcile an error's outcome using an immutable operation identifier.
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		s.poisoned.Store(true)
		return errors.Join(ErrCommitUnknown, err)
	}
	active = false
	return nil
}

func (s *Store) Read(ctx context.Context, fn func(Executor) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if s.poisoned.Load() {
		return ErrPoisoned
	}
	if fn == nil {
		return errors.New("nil sqlite read callback")
	}
	conn, err := s.readers.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return fn(conn)
}

// Checkpoint makes progress only when readers permit it; it cannot be treated
// as backup and intentionally truncates an active WAL.
func (s *Store) Checkpoint(ctx context.Context) (status WALStatus, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return status, ErrClosed
	}
	if s.poisoned.Load() {
		return status, ErrPoisoned
	}
	// TRUNCATE waits up to busy_timeout for active readers, reports blocked
	// readers, and bounds WAL growth. PASSIVE often returns success despite
	// leaving frames behind and was not a reliable maintenance signal.
	err = s.writer.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&status.Busy, &status.LogFrames, &status.CheckpointedFrames)
	if err != nil {
		return status, err
	}
	if status.Busy != 0 || (status.LogFrames >= 0 && status.CheckpointedFrames < status.LogFrames) {
		return status, fmt.Errorf("sqlite checkpoint incomplete: busy=%d frames=%d checkpointed=%d", status.Busy, status.LogFrames, status.CheckpointedFrames)
	}
	return status, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.readers != nil {
		err = errors.Join(err, s.readers.Close())
	}
	if s.writer != nil {
		err = errors.Join(err, s.writer.Close())
	}
	err = errors.Join(err, releaseLock(s.lock))
	return err
}

// ProbeDurability performs two independent starts, a committed challenge and
// a full close/reopen. It does NOT claim to be an SQLite-to-PostgreSQL migration.
func ProbeDurability(ctx context.Context, opt Options) (WALStatus, error) {
	s, err := Open(ctx, opt)
	if err != nil {
		return WALStatus{}, err
	}
	var bytes [16]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		_ = s.Close()
		return WALStatus{}, err
	}
	token := hex.EncodeToString(bytes[:])
	err = s.Write(ctx, func(q Executor) error {
		if _, e := q.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _launcher_dep00_probe (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`); e != nil {
			return e
		}
		_, e := q.ExecContext(ctx, `INSERT INTO _launcher_dep00_probe(id,created_at) VALUES (?,?)`, token, time.Now().UTC().UnixNano())
		return e
	})
	if err != nil {
		_ = s.Close()
		return WALStatus{}, err
	}
	if err = s.Close(); err != nil {
		return WALStatus{}, err
	}
	s, err = Open(ctx, opt)
	if err != nil {
		return WALStatus{}, err
	}
	defer s.Close()
	err = s.Read(ctx, func(q Executor) error {
		var id string
		if e := q.QueryRowContext(ctx, "SELECT id FROM _launcher_dep00_probe WHERE id=?", token).Scan(&id); e != nil {
			return e
		}
		if id != token {
			return fmt.Errorf("SQLite durability challenge mismatch")
		}
		return nil
	})
	if err != nil {
		return WALStatus{}, err
	}
	if err = s.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, "DELETE FROM _launcher_dep00_probe WHERE id=?", token)
		return e
	}); err != nil {
		return WALStatus{}, err
	}
	return s.Checkpoint(ctx)
}

func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

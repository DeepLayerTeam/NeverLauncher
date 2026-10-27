package sqlitedurable

// SQLite physical backups use VACUUM INTO on a separate read-only source
// connection. Unlike copying a live .db file, it includes committed WAL pages
// and produces a consistent snapshot without holding the application's writer.
// Restore is deliberately offline and rejects leftover WAL sidecars.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const BackupFormat = "neverlauncher-sqlite-snapshot-v1"

type BackupManifest struct {
	Format        string `json:"format"`
	CreatedAt     string `json:"createdAt"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
	SchemaVersion int    `json:"schemaVersion"`
	SQLiteVersion string `json:"sqliteVersion"`
}

func newToken() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func isSafeRegular(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe SQLite file %q (require regular 0600)", p)
	}
	return nil
}
func openSnapshotReader(ctx context.Context, path string) (*sql.DB, error) {
	// mode=ro prevents any mutation of the source. query_only=ON is deliberately
	// omitted: SQLite rejects VACUUM INTO under query_only even when mode=ro.
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=ro&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)&_pragma=trusted_schema(OFF)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	err = checkEngine(ctx, conn)
	if err == nil {
		err = pragmaInt(ctx, conn, "foreign_keys", 1)
	}
	err = errors.Join(err, conn.Close())
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}
func snapshotCheck(ctx context.Context, path string) (int, error) {
	if err := isSafeRegular(path); err != nil {
		return 0, err
	}
	db, err := openSnapshotReader(ctx, path)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return 0, err
	}
	if integrity != "ok" {
		return 0, fmt.Errorf("snapshot integrity_check: %s", integrity)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, err
	}
	hasForeignKeyError := rows.Next()
	rowErr := rows.Err()
	closeErr := rows.Close()
	if err = errors.Join(rowErr, closeErr); err != nil {
		return 0, err
	}
	if hasForeignKeyError {
		return 0, errors.New("snapshot foreign_key_check failed")
	}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}
func fileDigest(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
func createStage(dir string) (string, error) {
	f, err := os.CreateTemp(dir, ".neverlauncher-snapshot-*")
	if err != nil {
		return "", err
	}
	p := f.Name()
	if err = f.Chmod(0600); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		_ = os.Remove(p)
		return "", err
	}
	return p, nil
}
func writeManifest(path string, m BackupManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	stage, err := createStage(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	f, err := os.OpenFile(stage, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	// Never expose a truncated manifest, and never overwrite a previous one.
	return os.Link(stage, path)
}
func requireNewBackupPath(source, dest string) (string, string, error) {
	if source == "" || dest == "" || strings.ContainsAny(dest, "\x00\r\n") {
		return "", "", errors.New("missing or invalid backup path")
	}
	src, err := filepath.Abs(source)
	if err != nil {
		return "", "", err
	}
	dst, err := filepath.Abs(dest)
	if err != nil {
		return "", "", err
	}
	if src == dst || src == dst+".json" || dst == src+".json" {
		return "", "", errors.New("source and backup path overlap")
	}
	if err = verifyLocalPath(src); err != nil {
		return "", "", err
	}
	if err = isSafeRegular(src); err != nil {
		return "", "", err
	}
	if err = verifyLocalPath(dst); err != nil {
		return "", "", err
	}
	for _, p := range []string{dst, dst + ".json"} {
		if _, e := os.Lstat(p); e == nil {
			return "", "", fmt.Errorf("backup path already exists: %s", p)
		} else if !os.IsNotExist(e) {
			return "", "", e
		}
	}
	return src, dst, nil
}

// OnlineBackup works while the NeverLauncher API owns the source database.
// It never acquires the source owner lock, never checkpoints/truncates the WAL,
// and never replaces a previous backup. The .json sidecar is a checksum and
// metadata (not an authentication signature). Backups contain sensitive data.
func OnlineBackup(ctx context.Context, source, destination string) (m BackupManifest, err error) {
	src, dst, err := requireNewBackupPath(source, destination)
	if err != nil {
		return m, err
	}
	reader, err := openSnapshotReader(ctx, src)
	if err != nil {
		return m, err
	}
	defer reader.Close()
	temp, err := createStage(filepath.Dir(dst))
	if err != nil {
		return m, err
	}
	published := false
	linked := false
	manifestCreated := false
	defer func() {
		_ = os.Remove(temp)
		if !published {
			if linked {
				_ = os.Remove(dst)
			}
			if manifestCreated {
				_ = os.Remove(dst + ".json")
			}
		}
	}()
	if _, err = reader.ExecContext(ctx, "VACUUM INTO ?", temp); err != nil {
		return m, fmt.Errorf("SQLite online backup VACUUM INTO: %w", err)
	}
	f, e := os.OpenFile(temp, os.O_RDONLY, 0)
	if e != nil {
		return m, e
	}
	e = errors.Join(f.Sync(), f.Close())
	if e != nil {
		return m, e
	}
	v, e := snapshotCheck(ctx, temp)
	if e != nil {
		return m, e
	}
	size, digest, e := fileDigest(temp)
	if e != nil {
		return m, e
	}
	if size == 0 {
		return m, errors.New("empty SQLite backup")
	}
	m = BackupManifest{Format: BackupFormat, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SHA256: digest, Bytes: size, SchemaVersion: v, SQLiteVersion: EngineVersion}
	// Publish the immutable database and manifest; incomplete backup publication
	// is rejected by VerifyBackup and cleaned on reported errors.
	// Hardlink publishing is atomic and fails if a competing backup already exists.
	if err = os.Link(temp, dst); err != nil {
		return m, err
	}
	linked = true
	if err = syncDirectory(filepath.Dir(dst)); err != nil {
		return m, err
	}
	if err = writeManifest(dst+".json", m); err != nil {
		return m, err
	}
	manifestCreated = true
	if err = syncDirectory(filepath.Dir(dst)); err != nil {
		return m, err
	}
	published = true
	return m, nil
}

// VerifyBackup rejects absent, corrupted, mismatched, tampered, incomplete,
// incompatible, or logically invalid backups before any restore action.
func VerifyBackup(ctx context.Context, path string) (BackupManifest, error) {
	var m BackupManifest
	if path == "" {
		return m, errors.New("backup path required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return m, err
	}
	if err = verifyLocalPath(abs); err != nil {
		return m, err
	}
	if err = isSafeRegular(abs); err != nil {
		return m, err
	}
	side := abs + ".json"
	if err = isSafeRegular(side); err != nil {
		return m, err
	}
	f, err := os.Open(side)
	if err != nil {
		return m, err
	}
	dec := json.NewDecoder(io.LimitReader(f, 8193))
	dec.DisallowUnknownFields()
	err = dec.Decode(&m)
	var extra any
	if err == nil {
		if e := dec.Decode(&extra); e != io.EOF {
			err = errors.New("backup metadata has trailing content")
		}
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return m, err
	}
	if m.Format != BackupFormat || m.SQLiteVersion != EngineVersion || m.Bytes <= 0 || len(m.SHA256) != 64 || m.CreatedAt == "" {
		return m, errors.New("unsupported or invalid backup metadata")
	}
	if _, e := time.Parse(time.RFC3339Nano, m.CreatedAt); e != nil {
		return m, e
	}
	n, digest, err := fileDigest(abs)
	if err != nil {
		return m, err
	}
	if n != m.Bytes || digest != m.SHA256 {
		return m, errors.New("SQLite backup SHA-256 or length mismatch")
	}
	v, err := snapshotCheck(ctx, abs)
	if err != nil {
		return m, err
	}
	if v != m.SchemaVersion {
		return m, fmt.Errorf("SQLite backup schema %d != manifest %d", v, m.SchemaVersion)
	}
	return m, nil
}

// RestoreBackup requires a STOPPED backend. It holds the same OS owner lock
// used by sqlitedurable.Open and refuses WAL/SHM sidecars instead of risking
// replay of stale pages into the restored DB. The old database is retained via
// a durable same-filesystem hardlink for operator rollback.
func RestoreBackup(ctx context.Context, backup, target string, replace bool) (rollback string, err error) {
	if backup == "" || target == "" {
		return "", errors.New("backup and target required")
	}
	src, e := filepath.Abs(backup)
	if e != nil {
		return "", e
	}
	dst, e := filepath.Abs(target)
	if e != nil {
		return "", e
	}
	if src == dst || src == dst+".json" {
		return "", errors.New("source and target overlap")
	}
	if _, err = VerifyBackup(ctx, src); err != nil {
		return "", err
	}
	if err = verifyLocalPath(dst); err != nil {
		return "", err
	}
	lock, err := exclusiveLock(dst + ".owner.lock")
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, releaseLock(lock)) }()
	// Reverify under lock in case the backup was altered between calls.
	if _, err = VerifyBackup(ctx, src); err != nil {
		return "", err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e = os.Lstat(dst + suffix); e == nil {
			return "", fmt.Errorf("refusing restore: %s exists; shut down SQLite and checkpoint first", dst+suffix)
		} else if !os.IsNotExist(e) {
			return "", e
		}
	}
	old := false
	if st, e := os.Lstat(dst); e == nil {
		if !replace {
			return "", errors.New("target already exists; explicit --replace required")
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("unsafe restore target")
		}
		old = true
	} else if !os.IsNotExist(e) {
		return "", e
	}
	temp, err := createStage(filepath.Dir(dst))
	if err != nil {
		return "", err
	}
	defer os.Remove(temp)
	in, e := os.Open(src)
	if e != nil {
		return "", e
	}
	out, e := os.OpenFile(temp, os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		_ = in.Close()
		return "", e
	}
	_, e = io.Copy(out, in)
	e = errors.Join(e, in.Close())
	if e == nil {
		e = out.Sync()
	}
	e = errors.Join(e, out.Close())
	if e != nil {
		return "", e
	}
	// Compare copied bytes, not just SQLite page checks.
	_, copied, e := fileDigest(temp)
	if e != nil {
		return "", e
	}
	manifest, e := VerifyBackup(ctx, src)
	if e != nil {
		return "", e
	}
	if copied != manifest.SHA256 {
		return "", errors.New("backup changed during restore copy")
	}
	if _, err = snapshotCheck(ctx, temp); err != nil {
		return "", err
	}
	if old {
		tok, e := newToken()
		if e != nil {
			return "", e
		}
		rollback = dst + ".pre-restore-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10) + "-" + tok
		if err = os.Link(dst, rollback); err != nil {
			return "", fmt.Errorf("create rollback hardlink: %w", err)
		}
		if err = syncDirectory(filepath.Dir(dst)); err != nil {
			_ = os.Remove(rollback)
			return "", err
		}
	}
	if err = os.Rename(temp, dst); err != nil {
		return rollback, err
	}
	if err = syncDirectory(filepath.Dir(dst)); err != nil {
		return rollback, err
	}
	return rollback, nil
}

package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// Runtime components are stored in the SAME SQLite WAL file as the HTTP
// repository, under its exclusive process lock. Each component is committed
// synchronously before its caller may report success.
const sqliteRuntimeDDL0373 = `CREATE TABLE IF NOT EXISTS http_runtime_components_0373 (
 component TEXT PRIMARY KEY,
 format_version INTEGER NOT NULL CHECK(format_version=1),
 sequence INTEGER NOT NULL CHECK(sequence>=1),
 sha256 TEXT NOT NULL,
 payload BLOB NOT NULL
)`

func (r *SQLiteHTTPRepository0372) ReadRuntimeComponent0373(ctx context.Context, name string) ([]byte, bool, error) {
	if !runtimeComponentAllowed0373(name) {
		return nil, false, fmt.Errorf("invalid runtime component %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return nil, false, r.failed
	}
	var data []byte
	var digest string
	var version int
	err := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, `SELECT format_version,sha256,payload FROM http_runtime_components_0373 WHERE component=?`, name).Scan(&version, &digest, &data)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if version != 1 {
		return nil, false, fmt.Errorf("unsupported runtime component version %d", version)
	}
	sha := sha256.Sum256(data)
	if hex.EncodeToString(sha[:]) != digest {
		return nil, false, errors.New("runtime component digest mismatch")
	}
	return data, true, nil
}

func (r *SQLiteHTTPRepository0372) WriteRuntimeComponent0373(ctx context.Context, name string, data []byte) error {
	if !runtimeComponentAllowed0373(name) {
		return fmt.Errorf("invalid runtime component %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	sha := sha256.Sum256(data)
	err := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `INSERT INTO http_runtime_components_0373(component,format_version,sequence,sha256,payload)
VALUES (?,1,1,?,?) ON CONFLICT(component) DO UPDATE SET sequence=sequence+1,sha256=excluded.sha256,payload=excluded.payload`, name, hex.EncodeToString(sha[:]), data)
		return e
	})
	if err != nil {
		r.failed = fmt.Errorf("runtime component %s commit: %w", name, err)
		return r.failed
	}
	return nil
}

func runtimeComponentAllowed0373(name string) bool {
	switch name {
	case "sessions", "security", "passkeys", "bridge":
		return true
	}
	return false
}

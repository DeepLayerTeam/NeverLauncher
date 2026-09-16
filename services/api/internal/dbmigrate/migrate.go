package dbmigrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

//go:embed sql/*.sql
var migrationFS embed.FS

type Migration struct{ Version, Description, Checksum, SQL string }
type Status struct {
	Current    string   `json:"current"`
	Pending    []string `json:"pending,omitempty"`
	Unknown    []string `json:"unknown,omitempty"`
	Unverified []string `json:"unverified,omitempty"`
	Applied    int      `json:"applied"`
	Total      int      `json:"total"`
	Compatible bool     `json:"compatible"`
}

func Catalog() ([]Migration, error) {
	entries, err := migrationFS.ReadDir("sql")
	if err != nil {
		return nil, err
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrationFS.ReadFile("sql/" + e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, Migration{Version: strings.TrimSuffix(e.Name(), ".sql"), Description: e.Name(), Checksum: hex.EncodeToString(sum[:]), SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func hasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2)`, table, column).Scan(&exists)
	return exists, err
}

func ensureTracking(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, q := range []string{`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS version TEXT`, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT ''`, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''`, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ NOT NULL DEFAULT now()`} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	legacyID, err := hasColumn(ctx, db, "schema_migrations", "id")
	if err != nil {
		return err
	}
	if legacyID {
		if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET version=id WHERE version IS NULL AND id IS NOT NULL`); err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_schema_migrations_version_p0 ON schema_migrations(version)`)
	return err
}

func EvaluateApplied(applied map[string]string) (Status, error) {
	ms, err := Catalog()
	if err != nil {
		return Status{}, err
	}
	known := make(map[string]Migration, len(ms))
	for _, m := range ms {
		known[m.Version] = m
	}
	st := Status{Total: len(ms), Compatible: true}
	for version, checksum := range applied {
		m, ok := known[version]
		if !ok {
			st.Unknown = append(st.Unknown, version)
			continue
		}
		st.Applied++
		if st.Current == "" || version > st.Current {
			st.Current = version
		}
		if strings.TrimSpace(checksum) == "" {
			st.Unverified = append(st.Unverified, version)
			continue
		}
		if checksum != m.Checksum {
			st.Compatible = false
			return st, fmt.Errorf("checksum migration %s changed: database=%s binary=%s", version, checksum, m.Checksum)
		}
	}
	for _, m := range ms {
		if _, ok := applied[m.Version]; !ok {
			st.Pending = append(st.Pending, m.Version)
		}
	}
	sort.Strings(st.Unknown)
	sort.Strings(st.Unverified)
	if len(st.Unknown) > 0 {
		st.Compatible = false
		return st, fmt.Errorf("database contains migrations unknown to this binary: %s", strings.Join(st.Unknown, ","))
	}
	if len(st.Unverified) > 0 {
		st.Compatible = false
		return st, fmt.Errorf("database contains migrations without sealed checksum: %s; run migration apply with the matching binary", strings.Join(st.Unverified, ","))
	}
	return st, nil
}

func StatusOf(ctx context.Context, db *sql.DB) (Status, error) {
	if err := ensureTracking(ctx, db); err != nil {
		return Status{}, err
	}
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations WHERE version IS NOT NULL`)
	if err != nil {
		return Status{}, err
	}
	defer rows.Close()
	applied := map[string]string{}
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			return Status{}, err
		}
		applied[v] = c
	}
	if err := rows.Err(); err != nil {
		return Status{}, err
	}
	return EvaluateApplied(applied)
}

func validateExistingBeforeApply(ctx context.Context, db *sql.DB, ms []Migration) error {
	known := make(map[string]string, len(ms))
	for _, m := range ms {
		known[m.Version] = m.Checksum
	}
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations WHERE version IS NOT NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return err
		}
		expected, ok := known[version]
		if !ok {
			return fmt.Errorf("database contains migration %s unknown to this binary; refusing downgrade/apply", version)
		}
		if checksum != "" && checksum != expected {
			return fmt.Errorf("migration %s checksum mismatch", version)
		}
	}
	return rows.Err()
}

func Apply(ctx context.Context, db *sql.DB) (Status, error) {
	if err := db.PingContext(ctx); err != nil {
		return Status{}, err
	}
	// Serialize the whole validation/apply window across Backend and CLI migrators.
	// A per-migration transaction lock leaves a downgrade race where a newer binary
	// can commit an unknown migration after the older binary has validated its catalog.
	lockConn, err := db.Conn(ctx)
	if err != nil {
		return Status{}, err
	}
	defer lockConn.Close()
	if _, err := lockConn.ExecContext(ctx, `SELECT pg_advisory_lock(718033100100)`); err != nil {
		return Status{}, fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = lockConn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock(718033100100)`)
	}()

	if err := ensureTracking(ctx, db); err != nil {
		return Status{}, err
	}
	legacyID, err := hasColumn(ctx, db, "schema_migrations", "id")
	if err != nil {
		return Status{}, err
	}
	ms, err := Catalog()
	if err != nil {
		return Status{}, err
	}
	if err := validateExistingBeforeApply(ctx, db, ms); err != nil {
		return Status{}, err
	}
	for _, m := range ms {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return Status{}, err
		}
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(718033100100)`); err != nil {
			tx.Rollback()
			return Status{}, err
		}
		var checksum string
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, m.Version).Scan(&checksum)
		if err == nil {
			if checksum != "" && checksum != m.Checksum {
				tx.Rollback()
				return Status{}, fmt.Errorf("migration %s checksum mismatch", m.Version)
			}
			if checksum == "" {
				if _, err = tx.ExecContext(ctx, `UPDATE schema_migrations SET checksum=$2,description=CASE WHEN description='' THEN $3 ELSE description END WHERE version=$1 AND checksum=''`, m.Version, m.Checksum, m.Description); err != nil {
					tx.Rollback()
					return Status{}, fmt.Errorf("seal migration %s checksum: %w", m.Version, err)
				}
			}
			if err = tx.Commit(); err != nil {
				return Status{}, err
			}
			continue
		}
		if err != sql.ErrNoRows {
			tx.Rollback()
			return Status{}, err
		}
		if _, err = tx.ExecContext(ctx, m.SQL); err != nil {
			tx.Rollback()
			return Status{}, fmt.Errorf("apply %s: %w", m.Version, err)
		}
		if legacyID {
			_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(id,version,checksum,description,applied_at) VALUES($1,$1,$2,$3,$4)`, m.Version, m.Checksum, m.Description, time.Now().UTC())
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,checksum,description,applied_at) VALUES($1,$2,$3,$4)`, m.Version, m.Checksum, m.Description, time.Now().UTC())
		}
		if err != nil {
			tx.Rollback()
			return Status{}, err
		}
		if err = tx.Commit(); err != nil {
			return Status{}, err
		}
	}
	return StatusOf(ctx, db)
}

func LatestVersion() string {
	ms, err := Catalog()
	if err != nil || len(ms) == 0 {
		return ""
	}
	return ms[len(ms)-1].Version
}

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
	Current    string
	Pending    []string
	Applied    int
	Total      int
	Compatible bool
}

func migrations() ([]Migration, error) {
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

func StatusOf(ctx context.Context, db *sql.DB) (Status, error) {
	if err := ensureTracking(ctx, db); err != nil {
		return Status{}, err
	}
	ms, err := migrations()
	if err != nil {
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
	st := Status{Total: len(ms), Compatible: true}
	for _, m := range ms {
		if c, ok := applied[m.Version]; ok {
			st.Applied++
			st.Current = m.Version
			if c != "" && c != m.Checksum {
				st.Compatible = false
				return st, fmt.Errorf("checksum migration %s changed: database=%s binary=%s", m.Version, c, m.Checksum)
			}
		} else {
			st.Pending = append(st.Pending, m.Version)
		}
	}
	return st, nil
}

func Apply(ctx context.Context, db *sql.DB) (Status, error) {
	if err := db.PingContext(ctx); err != nil {
		return Status{}, err
	}
	if err := ensureTracking(ctx, db); err != nil {
		return Status{}, err
	}
	legacyID, err := hasColumn(ctx, db, "schema_migrations", "id")
	if err != nil {
		return Status{}, err
	}
	ms, err := migrations()
	if err != nil {
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
	ms, err := migrations()
	if err != nil || len(ms) == 0 {
		return ""
	}
	return ms[len(ms)-1].Version
}

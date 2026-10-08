package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// PersistenceSnapshotRepository хранит 0.10.0 write-through snapshots для
// security/session/server-bridge state. Это не заменяет нормализованные таблицы
// миграций 0092-0096, а дополняет их быстрым bootstrap-контуром после рестарта API.
type PersistenceSnapshotRepository interface {
	EnsurePersistence(ctx context.Context) error
	SavePersistenceSnapshot(ctx context.Context, kind, schemaVersion string, payload map[string]any) error
	LoadLatestPersistenceSnapshot(ctx context.Context, kind string) (map[string]any, bool, error)
}

type SQLPersistenceSnapshotRepository struct {
	DB *sql.DB
}

func NewSQLPersistenceSnapshotRepository(db *sql.DB) *SQLPersistenceSnapshotRepository {
	return &SQLPersistenceSnapshotRepository{DB: db}
}

func (r *SQLPersistenceSnapshotRepository) EnsurePersistence(ctx context.Context) error {
	if _, err := r.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS neverlauncher_persistence_snapshots_950 (id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL, schema_version TEXT NOT NULL, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	_, err := r.DB.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_neverlauncher_persistence_snapshots_950_kind_created ON neverlauncher_persistence_snapshots_950 (kind, created_at DESC)`)
	return err
}

func (r *SQLPersistenceSnapshotRepository) SavePersistenceSnapshot(ctx context.Context, kind, schemaVersion string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = r.DB.ExecContext(ctx, `INSERT INTO neverlauncher_persistence_snapshots_950 (kind, schema_version, payload, created_at) VALUES ($1,$2,$3,$4)`, kind, schemaVersion, string(raw), time.Now().UTC())
	return err
}

func (r *SQLPersistenceSnapshotRepository) LoadLatestPersistenceSnapshot(ctx context.Context, kind string) (map[string]any, bool, error) {
	var raw string
	err := r.DB.QueryRowContext(ctx, `SELECT payload::text FROM neverlauncher_persistence_snapshots_950 WHERE kind=$1 ORDER BY created_at DESC, id DESC LIMIT 1`, kind).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, false, err
	}
	return payload, true, nil
}

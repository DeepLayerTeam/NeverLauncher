-- 0.33.4: source UUID mapping snapshots, fenced by the migration-run lock.
-- No credentials, raw FileAuth JSON, password hashes or sessions are persisted.
CREATE TABLE migration_identity_snapshots_0334 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 source_sha256 CHAR(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
 inventory_sha256 CHAR(64) NOT NULL CHECK (inventory_sha256 ~ '^[0-9a-f]{64}$'),
 entries_sha256 CHAR(64) NOT NULL CHECK (entries_sha256 ~ '^[0-9a-f]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE migration_identity_rows_0334 (
 run_id TEXT NOT NULL REFERENCES migration_identity_snapshots_0334(run_id) ON DELETE RESTRICT,
 ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 200000),
 provider TEXT NOT NULL CHECK (provider IN ('fileauth','sql')),
 source_id TEXT NOT NULL CHECK (char_length(source_id) BETWEEN 1 AND 256),
 username VARCHAR(16) NOT NULL CHECK (username ~ '^[A-Za-z0-9_]{3,16}$'),
 minecraft_uuid CHAR(36) NOT NULL CHECK (minecraft_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 source_path TEXT NOT NULL CHECK (char_length(source_path) BETWEEN 1 AND 2048),
 target_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
 status TEXT NOT NULL CHECK (status IN ('matched','pending_import','blocked')),
 reason TEXT NOT NULL,
 PRIMARY KEY(run_id,ordinal)
);
CREATE INDEX migration_identity_rows_0334_uuid ON migration_identity_rows_0334(run_id,minecraft_uuid);
CREATE INDEX migration_identity_rows_0334_state ON migration_identity_rows_0334(run_id,status);

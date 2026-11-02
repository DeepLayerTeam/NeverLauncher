-- Content migration commits profile, workspace and receipt in ONE transaction.
-- The source archive is NOT stored in PostgreSQL; encrypted, hash-pinned
-- workspace objects are staged through the existing authenticated store.
CREATE TABLE migration_content_0337 (
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 profile_path TEXT NOT NULL CHECK (char_length(profile_path) BETWEEN 1 AND 1024),
 source_sha256 CHAR(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
 manifest_sha256 CHAR(64) NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 files_sha256 CHAR(64) NOT NULL CHECK (files_sha256 ~ '^[0-9a-f]{64}$'),
 profile_id TEXT NOT NULL,
 workspace_id TEXT NOT NULL UNIQUE REFERENCES build_workspaces_0226(id) ON DELETE RESTRICT,
 owner_id TEXT NOT NULL,
 report JSONB NOT NULL CHECK (jsonb_typeof(report)='object'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (run_id, profile_path),
 UNIQUE (run_id, profile_id)
);

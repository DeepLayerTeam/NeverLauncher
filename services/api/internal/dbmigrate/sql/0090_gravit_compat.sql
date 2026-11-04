-- 0.33.2: sanitized Gravit source assessments, not raw source archives.
-- The FK ensures assessments cannot outlive their durable migration run.
CREATE TABLE migration_compatibility_0332 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 source_sha256 TEXT NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
 report JSONB NOT NULL CHECK (jsonb_typeof(report) = 'object'),
 assessed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

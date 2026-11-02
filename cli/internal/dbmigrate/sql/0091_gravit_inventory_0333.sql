-- 0.33.3: durable sanitized source inventory only. Source bytes/credentials
-- never enter PostgreSQL. Exports are regenerated from verified client ZIPs.
CREATE TABLE migration_source_inventory_0333 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 source_sha256 TEXT NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
 manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 inventory JSONB NOT NULL CHECK (jsonb_typeof(inventory) = 'object'),
 inventoried_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

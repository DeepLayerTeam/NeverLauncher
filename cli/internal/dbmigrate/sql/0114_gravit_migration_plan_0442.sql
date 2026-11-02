-- Persist only the sanitized, deterministic dry-run plan. No source credentials
-- or uploaded bytes are stored here. A plan is NOT a cutover authorization.
CREATE TABLE migration_plan_0442 (
  run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256)=64),
  inventory_sha256 TEXT NOT NULL CHECK (length(inventory_sha256)=64),
  target_sha256 TEXT NOT NULL CHECK (length(target_sha256)=64),
  plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256)=64),
  plan JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

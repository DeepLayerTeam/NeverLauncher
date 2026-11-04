-- 0.33.1: persistent, fenced, resumable migration execution. No Gravit trust is imported here.
CREATE TABLE migration_runs_0331 (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 idempotency_key TEXT NOT NULL,
 source_kind TEXT NOT NULL CHECK (source_kind = 'gravit'),
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','paused','failed','prepared')),
 step TEXT NOT NULL DEFAULT 'target_check' CHECK (step IN ('target_check','target_inventory','source_assessment')),
 revision BIGINT NOT NULL DEFAULT 0,
 fence BIGINT NOT NULL DEFAULT 0,
 lease_owner TEXT,
 lease_until TIMESTAMPTZ,
 result JSONB NOT NULL DEFAULT '{}'::jsonb,
 last_error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(project_id, idempotency_key),
 CHECK ((lease_owner IS NULL) = (lease_until IS NULL))
);
CREATE INDEX migration_runs_0331_project ON migration_runs_0331(project_id, created_at DESC);
CREATE TABLE migration_events_0331 (
 seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL,
 step TEXT NOT NULL,
 revision BIGINT NOT NULL,
 detail JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX migration_events_0331_run ON migration_events_0331(run_id, seq);

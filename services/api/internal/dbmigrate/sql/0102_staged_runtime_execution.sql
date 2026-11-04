-- V01/V02: record each real staged execution by immutable release snapshot.
-- These are observational reports only, not trusted validation evidence.
CREATE TABLE package_staged_runtime_runs_0342 (
 run_id TEXT PRIMARY KEY,
 package_id TEXT NOT NULL REFERENCES release_versions(id),
 project_id TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
 stages JSONB NOT NULL CHECK (jsonb_typeof(stages) = 'object'),
 started_at TIMESTAMPTZ NOT NULL,
 finished_at TIMESTAMPTZ NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK(finished_at >= started_at)
);
CREATE INDEX package_staged_runtime_runs_by_package_0342 ON package_staged_runtime_runs_0342(package_id,received_at DESC);

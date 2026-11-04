-- A signed attestation never changes protected release eligibility in 0.34.5.
CREATE TABLE package_validation_attestations_0345 (
 run_id TEXT PRIMARY KEY REFERENCES package_staged_runtime_runs_0342(run_id),
 package_id TEXT NOT NULL REFERENCES release_versions(id),
 project_id TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
 evidence JSONB NOT NULL CHECK (jsonb_typeof(evidence)='object'),
 signature TEXT NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX package_validation_attestations_pkg_0345 ON package_validation_attestations_0345(package_id,received_at DESC);

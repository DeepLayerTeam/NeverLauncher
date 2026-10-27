-- Auth import receipts are committed in the SAME transaction as the accounts.
-- Password verifiers are stored only in users.password_hash, never in receipts,
-- snapshots, API responses, events or audit metadata.
CREATE TABLE migration_auth_imports_0335 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 source_sha256 CHAR(64) NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 identity_sha256 CHAR(64) NOT NULL CHECK(identity_sha256 ~ '^[0-9a-f]{64}$'),
 decision_sha256 CHAR(64) NOT NULL CHECK(decision_sha256 ~ '^[0-9a-f]{64}$'),
 report JSONB NOT NULL CHECK(jsonb_typeof(report)='object'),
 imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

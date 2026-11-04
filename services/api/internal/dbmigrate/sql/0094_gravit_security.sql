-- 0.33.6: durable, immutable receipt and per-user targets for explicit trust reset.
-- Never save imported private keys, bearer tokens, device secrets, old trust
-- anchors or Guard attestations. Updates are transactional with this receipt.
CREATE TABLE migration_security_targets_0336 (
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 expected_name VARCHAR(16) NOT NULL,
 expected_uuid CHAR(36) NOT NULL,
 PRIMARY KEY(run_id,user_id)
);
CREATE INDEX migration_security_targets_user_0336 ON migration_security_targets_0336(user_id);
CREATE TABLE migration_security_resets_0336 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 auth_decision_sha256 CHAR(64) NOT NULL CHECK(auth_decision_sha256 ~ '^[0-9a-f]{64}$'),
 active_jwt_kid TEXT NOT NULL CHECK (char_length(active_jwt_kid) BETWEEN 1 AND 96),
 manifest_public_sha256 CHAR(64) NOT NULL CHECK(manifest_public_sha256 ~ '^[0-9a-f]{64}$'),
 report JSONB NOT NULL CHECK(jsonb_typeof(report)='object'),
 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

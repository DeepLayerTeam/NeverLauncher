-- Challenges exist before a worker executes. Neither a report nor attestation
-- may retroactively issue its own nonce. Revocations are permanent.
CREATE TABLE package_validation_challenges_0346 (
 run_id TEXT PRIMARY KEY,
 nonce TEXT NOT NULL UNIQUE CHECK (nonce ~ '^[0-9a-f]{64}$'),
 package_id TEXT NOT NULL REFERENCES release_versions(id),
 project_id TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
 target_matrix_sha256 TEXT NOT NULL CHECK (target_matrix_sha256 ~ '^[0-9a-f]{64}$'),
 issued_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '2 hours')
);
CREATE TABLE package_validation_revoked_keys_0346 (
 fingerprint TEXT PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
 actor TEXT NOT NULL,
 reason TEXT NOT NULL,
 revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX package_validation_challenges_by_package_0346 ON package_validation_challenges_0346(package_id,issued_at DESC);
-- Forbid a second attestation at the DB boundary even if concurrently posted.
-- Existing attestation table already has PRIMARY KEY(run_id).

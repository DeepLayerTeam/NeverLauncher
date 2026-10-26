-- Expand, never delete, challenge-purpose allowlist. PostgreSQL migration is atomic.
ALTER TABLE device_challenges DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;
ALTER TABLE device_challenges ADD CONSTRAINT device_challenges_purpose_check CHECK (purpose IN (
 'register','session-bind','attest','key-rotate','key-recover',
 'guard-attest-v1','guard-launch-v1','guard-attest-v2','guard-continuous-join-v2',
 'serverbridge-verified-plan-v1','hardware-certify'
));

-- NeverLauncher 0.31.2: only server-verified TPM Certify results, not client claims.
CREATE TABLE IF NOT EXISTS device_hardware_evidence_0312 (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 user_id TEXT NOT NULL,
 device_id TEXT NOT NULL REFERENCES trusted_devices(id) ON DELETE CASCADE,
 session_id TEXT NOT NULL,
 binding_epoch BIGINT NOT NULL CHECK(binding_epoch>0),
 key_fingerprint TEXT NOT NULL CHECK(key_fingerprint ~ '^[0-9a-f]{64}$'),
 root_id TEXT NOT NULL,
 root_fingerprint TEXT NOT NULL CHECK(root_fingerprint ~ '^[0-9a-f]{64}$'),
 ak_fingerprint TEXT NOT NULL CHECK(ak_fingerprint ~ '^[0-9a-f]{64}$'),
 challenge_id TEXT NOT NULL UNIQUE,
 verified_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>verified_at AND expires_at<=verified_at+INTERVAL '1 hour 1 second')
);
CREATE INDEX IF NOT EXISTS device_hardware_evidence_latest_0312 ON device_hardware_evidence_0312(user_id,device_id,verified_at DESC);

-- 0.31.5 measured boot: separate persistence, separate attestation purpose.
ALTER TABLE device_challenges DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;
ALTER TABLE device_challenges ADD CONSTRAINT device_challenges_purpose_check CHECK (purpose IN (
 'register','session-bind','attest','key-rotate','key-recover',
 'guard-attest-v1','guard-launch-v1','guard-attest-v2','guard-continuous-join-v2',
 'serverbridge-verified-plan-v1','hardware-certify','measured-boot-quote'
));
CREATE TABLE IF NOT EXISTS device_measured_boot_0315 (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 user_id TEXT NOT NULL,
 device_id TEXT NOT NULL REFERENCES trusted_devices(id) ON DELETE CASCADE,
 session_id TEXT NOT NULL,
 binding_epoch BIGINT NOT NULL CHECK(binding_epoch>0),
 key_fingerprint TEXT NOT NULL CHECK(key_fingerprint ~ '^[0-9a-f]{64}$'),
 root_id TEXT NOT NULL,
 root_fingerprint TEXT NOT NULL CHECK(root_fingerprint ~ '^[0-9a-f]{64}$'),
 ak_fingerprint TEXT NOT NULL CHECK(ak_fingerprint ~ '^[0-9a-f]{64}$'),
 policy_id TEXT NOT NULL,
 policy_hash TEXT NOT NULL CHECK(policy_hash ~ '^[0-9a-f]{64}$'),
 pcr_digest TEXT NOT NULL CHECK(pcr_digest ~ '^[0-9a-f]{64}$'),
 challenge_id TEXT NOT NULL UNIQUE,
 verified_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>verified_at AND expires_at<=verified_at+INTERVAL '6 minutes')
);
CREATE INDEX IF NOT EXISTS device_measured_boot_latest_0315 ON device_measured_boot_0315(user_id,device_id,verified_at DESC);

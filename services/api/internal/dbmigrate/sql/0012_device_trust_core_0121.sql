-- NeverLauncher 0.12.1 — Device Trust Core + persistent device registry.
-- Existing auth_sessions.device_id remains an untrusted client label for compatibility.
-- trusted_device_id is populated only after an Ed25519 proof-of-possession ceremony.

CREATE TABLE IF NOT EXISTS trusted_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    trust_state TEXT NOT NULL DEFAULT 'verified',
    assurance TEXT NOT NULL DEFAULT 'proof-of-possession',
    key_algorithm TEXT NOT NULL DEFAULT 'ed25519',
    public_key TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL DEFAULT '',
    client_version TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    last_ip TEXT NOT NULL DEFAULT '',
    last_user_agent TEXT NOT NULL DEFAULT '',
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT NOT NULL DEFAULT '',
    CONSTRAINT trusted_devices_status_check CHECK (status IN ('active','revoked')),
    CONSTRAINT trusted_devices_trust_state_check CHECK (trust_state IN ('verified','revoked')),
    CONSTRAINT trusted_devices_assurance_check CHECK (assurance='proof-of-possession'),
    CONSTRAINT trusted_devices_key_algorithm_check CHECK (key_algorithm='ed25519'),
    CONSTRAINT trusted_devices_name_check CHECK (length(btrim(name)) BETWEEN 1 AND 96),
    CONSTRAINT trusted_devices_fingerprint_check CHECK (key_fingerprint ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_status ON trusted_devices(user_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_last_verified ON trusted_devices(user_id,last_verified_at DESC) WHERE status='active';

CREATE TABLE IF NOT EXISTS device_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT device_challenges_purpose_check CHECK (purpose IN ('register','session-bind')),
    CONSTRAINT device_challenges_hash_check CHECK (challenge_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT device_challenges_expiry_check CHECK (expires_at>created_at)
);
CREATE INDEX IF NOT EXISTS idx_device_challenges_expiry ON device_challenges(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_device_challenges_user_device ON device_challenges(user_id,device_id,purpose,created_at DESC);

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS trusted_device_id TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS device_trust_state TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS device_verified_at TIMESTAMPTZ;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_sessions_device_trust_state_check') THEN
        ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_device_trust_state_check
            CHECK (device_trust_state IN ('unverified','verified','revoked'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_sessions_trusted_device_fk') THEN
        ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_trusted_device_fk
            FOREIGN KEY(trusted_device_id) REFERENCES trusted_devices(id)
            DEFERRABLE INITIALLY IMMEDIATE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_trusted_device ON auth_sessions(trusted_device_id,status)
    WHERE trusted_device_id IS NOT NULL;

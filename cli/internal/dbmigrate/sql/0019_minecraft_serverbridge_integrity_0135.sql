-- NeverLauncher 0.13.5: persist the verified Guard launch snapshot on the
-- Minecraft credential so every later validate/join/ServerBridge decision can
-- re-evaluate the release allowlist instead of trusting a one-time exchange.
ALTER TABLE minecraft_sessions
    ADD COLUMN IF NOT EXISTS integrity_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS guard_attestation_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS guard_evidence_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS guard_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS launcher_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS launcher_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS integrity_verified_at TIMESTAMPTZ NULL;

ALTER TABLE minecraft_sessions
    DROP CONSTRAINT IF EXISTS minecraft_sessions_guard_attestation_sha256_check,
    ADD CONSTRAINT minecraft_sessions_guard_attestation_sha256_check CHECK (guard_attestation_sha256 = '' OR guard_attestation_sha256 ~ '^[0-9a-f]{64}$'),
    DROP CONSTRAINT IF EXISTS minecraft_sessions_guard_evidence_sha256_check,
    ADD CONSTRAINT minecraft_sessions_guard_evidence_sha256_check CHECK (guard_evidence_sha256 = '' OR guard_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    DROP CONSTRAINT IF EXISTS minecraft_sessions_guard_sha256_check,
    ADD CONSTRAINT minecraft_sessions_guard_sha256_check CHECK (guard_sha256 = '' OR guard_sha256 ~ '^[0-9a-f]{64}$'),
    DROP CONSTRAINT IF EXISTS minecraft_sessions_launcher_sha256_check,
    ADD CONSTRAINT minecraft_sessions_launcher_sha256_check CHECK (launcher_sha256 = '' OR launcher_sha256 ~ '^[0-9a-f]{64}$');

CREATE INDEX IF NOT EXISTS idx_minecraft_sessions_integrity_release_0135
    ON minecraft_sessions(launcher_version, guard_sha256, launcher_sha256)
    WHERE integrity_verified = TRUE AND status = 'active';

-- NeverLauncher 0.11.7 — Passkeys / WebAuthn + MFA 2.0.
-- WebAuthn challenges are single-use and PostgreSQL-backed for multi-instance deployments.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    user_handle BYTEA NOT NULL,
    public_key_cose BYTEA NOT NULL,
    algorithm INTEGER NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK(sign_count >= 0),
    aaguid BYTEA NOT NULL DEFAULT ''::bytea,
    transports JSONB NOT NULL DEFAULT '[]'::jsonb,
    friendly_name TEXT NOT NULL DEFAULT 'Passkey',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_status ON webauthn_credentials(user_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    challenge BYTEA NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id, purpose, created_at DESC);

CREATE TABLE IF NOT EXISTS mfa_policies (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    requirement TEXT NOT NULL DEFAULT 'optional' CHECK(requirement IN ('optional','required','phishing-resistant')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS auth_methods JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS auth_strength TEXT NOT NULL DEFAULT 'single-factor';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS identity_id TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'local';
CREATE INDEX IF NOT EXISTS idx_auth_sessions_strength ON auth_sessions(user_id, auth_strength, auth_time DESC) WHERE status='active';

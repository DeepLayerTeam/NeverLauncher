-- NeverLauncher 0.11.6: encrypted external provider credentials.
-- encrypted_refresh_token contains an application-layer AES-GCM envelope. Plaintext
-- Microsoft/OIDC refresh tokens are never stored in PostgreSQL.
CREATE TABLE IF NOT EXISTS provider_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_id TEXT NOT NULL REFERENCES auth_identities(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    encrypted_refresh_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_refreshed_at TIMESTAMPTZ,
    UNIQUE (user_id, provider),
    UNIQUE (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_provider_credentials_identity ON provider_credentials(identity_id);
CREATE INDEX IF NOT EXISTS idx_provider_credentials_provider ON provider_credentials(provider);

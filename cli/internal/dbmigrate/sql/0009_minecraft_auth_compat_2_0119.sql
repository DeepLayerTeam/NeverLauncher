-- NeverLauncher 0.11.9 — Minecraft Auth Compatibility 2.0.
-- Separates canonical Never users/sessions from persistent Minecraft profiles and
-- opaque Yggdrasil-compatible session tokens.

CREATE TABLE IF NOT EXISTS minecraft_profiles (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT minecraft_profiles_name_length CHECK (char_length(name) BETWEEN 3 AND 16),
    CONSTRAINT minecraft_profiles_name_format CHECK (name ~ '^[A-Za-z0-9_]+$')
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_minecraft_profiles_name_ci ON minecraft_profiles(lower(name));

CREATE TABLE IF NOT EXISTS minecraft_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    never_session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    profile_uuid TEXT NOT NULL REFERENCES minecraft_profiles(uuid) ON DELETE CASCADE,
    client_token TEXT NOT NULL DEFAULT '',
    access_token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT NOT NULL DEFAULT '',
    CONSTRAINT minecraft_sessions_status_check CHECK (status IN ('active','revoked'))
);
CREATE INDEX IF NOT EXISTS idx_minecraft_sessions_user_status ON minecraft_sessions(user_id,status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_minecraft_sessions_never_session ON minecraft_sessions(never_session_id,status);
CREATE INDEX IF NOT EXISTS idx_minecraft_sessions_expires ON minecraft_sessions(expires_at);

CREATE TABLE IF NOT EXISTS minecraft_joins (
    username TEXT NOT NULL,
    username_normalized TEXT NOT NULL,
    profile_uuid TEXT NOT NULL REFERENCES minecraft_profiles(uuid) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    minecraft_session_id TEXT NOT NULL REFERENCES minecraft_sessions(id) ON DELETE CASCADE,
    server_id TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(username_normalized, server_id)
);
CREATE INDEX IF NOT EXISTS idx_minecraft_joins_expires ON minecraft_joins(expires_at);

-- NeverLauncher 0.11.8 — Session Management 2.0.
-- Adds device metadata and observable risk state without weakening the existing
-- refresh-token family source of truth.

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS last_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS last_user_agent TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS risk_state TEXT NOT NULL DEFAULT 'normal';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS risk_reasons JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS risk_updated_at TIMESTAMPTZ;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS device_renamed_at TIMESTAMPTZ;

UPDATE auth_sessions
SET last_ip = CASE WHEN last_ip = '' THEN ip ELSE last_ip END,
    last_user_agent = CASE WHEN last_user_agent = '' THEN user_agent ELSE last_user_agent END
WHERE last_ip = '' OR last_user_agent = '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'auth_sessions_risk_state_check'
    ) THEN
        ALTER TABLE auth_sessions
            ADD CONSTRAINT auth_sessions_risk_state_check
            CHECK (risk_state IN ('normal','elevated','compromised'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_provider_active
    ON auth_sessions(provider, last_seen_at DESC)
    WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_auth_sessions_risk_active
    ON auth_sessions(risk_state, last_seen_at DESC)
    WHERE status='active';

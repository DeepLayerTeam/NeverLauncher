-- NeverLauncher 0.20.12: Доверие, Восстановление и Сертификация.

CREATE TABLE IF NOT EXISTS extension_trust_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    mode TEXT NOT NULL DEFAULT 'strict' CHECK (mode IN ('strict','audit')),
    allowed_publishers JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(allowed_publishers)='array'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO extension_trust_policy(singleton,mode,allowed_publishers)
VALUES(TRUE,'strict','[]'::jsonb) ON CONFLICT(singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS extension_quarantine (
    id TEXT PRIMARY KEY,
    package_identity TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    extension_id TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    publisher_id TEXT NOT NULL DEFAULT '',
    key_fingerprint TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    storage_project TEXT NOT NULL DEFAULT '',
    storage_version TEXT NOT NULL DEFAULT '',
    storage_path TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ,
    released_by TEXT NOT NULL DEFAULT '',
    CONSTRAINT extension_quarantine_identity_02012 CHECK (package_identity ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT extension_quarantine_sha_02012 CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT extension_quarantine_reason_02012 CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
    CONSTRAINT extension_quarantine_state_02012 CHECK ((active AND released_at IS NULL AND released_by='') OR (NOT active AND released_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_extension_quarantine_active_02012 ON extension_quarantine(package_identity) WHERE active;
CREATE INDEX IF NOT EXISTS idx_extension_quarantine_created_02012 ON extension_quarantine(created_at DESC);

CREATE TABLE IF NOT EXISTS extension_emergency_disables (
    extension_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cleared_at TIMESTAMPTZ,
    cleared_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(extension_id,scope,scope_id),
    CONSTRAINT extension_emergency_disables_scope_02012 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(btrim(scope_id))>0)),
    CONSTRAINT extension_emergency_disables_reason_02012 CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
    CONSTRAINT extension_emergency_disables_source_02012 CHECK (length(btrim(source)) BETWEEN 1 AND 128),
    CONSTRAINT extension_emergency_disables_state_02012 CHECK ((cleared_at IS NULL AND cleared_by='') OR cleared_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_extension_emergency_disables_active_02012 ON extension_emergency_disables(scope,scope_id,extension_id) WHERE cleared_at IS NULL;

CREATE OR REPLACE FUNCTION neverlauncher_revoke_extension_key_02012(p_publisher TEXT, p_fingerprint TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    UPDATE extension_registry_publisher_keys
       SET active=FALSE, revoked_at=COALESCE(revoked_at,now())
     WHERE publisher_id=p_publisher AND fingerprint=p_fingerprint;
    IF NOT FOUND THEN RAISE EXCEPTION 'publisher key not found'; END IF;
END;
$$;

COMMENT ON TABLE extension_trust_policy IS 'NeverExtensions registry-wide publisher allow policy (0.20.12).';
COMMENT ON TABLE extension_quarantine IS 'Persistent fail-closed quarantine for suspicious or revoked extension artifacts.';
COMMENT ON TABLE extension_emergency_disables IS 'Persistent NeverExtensions emergency kill-switch and crash-loop protection state.';

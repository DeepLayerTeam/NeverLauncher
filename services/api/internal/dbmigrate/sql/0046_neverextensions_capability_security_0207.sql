-- NeverLauncher 0.20.7: explicit capability grants and encrypted extension secrets.
-- Manifest permissions are requests only. Effective access is requested ∩ granted.

CREATE TABLE IF NOT EXISTS extension_permission_grants (
    extension_id TEXT NOT NULL REFERENCES extensions(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    permission TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, scope, scope_id, permission),
    CONSTRAINT extension_permission_grants_scope_0207 CHECK (scope IN ('global','project')),
    CONSTRAINT extension_permission_grants_scope_id_0207 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(btrim(scope_id)) > 0)),
    CONSTRAINT extension_permission_grants_permission_0207 CHECK (permission ~ '^[a-z0-9][a-z0-9._:-]{1,127}$'),
    CONSTRAINT extension_permission_grants_actor_0207 CHECK (length(btrim(granted_by)) BETWEEN 1 AND 255)
);

CREATE INDEX IF NOT EXISTS idx_extension_permission_grants_lookup_0207
    ON extension_permission_grants(extension_id, permission, scope, scope_id);

CREATE TABLE IF NOT EXISTS extension_secrets (
    extension_id TEXT NOT NULL REFERENCES extensions(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, scope, scope_id, name),
    CONSTRAINT extension_secrets_scope_0207 CHECK (scope IN ('global','project')),
    CONSTRAINT extension_secrets_scope_id_0207 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(btrim(scope_id)) > 0)),
    CONSTRAINT extension_secrets_name_0207 CHECK (name ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    CONSTRAINT extension_secrets_ciphertext_0207 CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592),
    CONSTRAINT extension_secrets_nonce_0207 CHECK (octet_length(nonce) = 12),
    CONSTRAINT extension_secrets_key_version_0207 CHECK (length(btrim(key_version)) BETWEEN 1 AND 64),
    CONSTRAINT extension_secrets_actor_0207 CHECK (length(btrim(updated_by)) BETWEEN 1 AND 255)
);

CREATE INDEX IF NOT EXISTS idx_extension_secrets_lookup_0207
    ON extension_secrets(extension_id, scope, scope_id, name);

COMMENT ON TABLE extension_permission_grants IS 'Explicit NeverExtensions capability approvals. Manifest permission declarations do not grant access.';
COMMENT ON TABLE extension_secrets IS 'AES-256-GCM encrypted extension secrets; plaintext is available only through the authenticated capability broker.';

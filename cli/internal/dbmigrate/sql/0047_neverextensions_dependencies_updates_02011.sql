-- NeverLauncher 0.20.11: dependency/update разрешатель хранение.
-- Добавляет API совместимость привязанный, точный область закрепляет, HA обновление аренды и
-- долговременный compensation-транзакция записывает.

ALTER TABLE extension_registry_compatibility
    ADD COLUMN IF NOT EXISTS min_api TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS max_api TEXT NOT NULL DEFAULT '';

DO $$ BEGIN
    ALTER TABLE extension_registry_compatibility
        ADD CONSTRAINT extension_registry_compatibility_min_api_02011
        CHECK (min_api='' OR min_api ~ '^[0-9]+\.[0-9]+(\.[0-9]+)?$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE extension_registry_compatibility
        ADD CONSTRAINT extension_registry_compatibility_max_api_02011
        CHECK (max_api='' OR max_api ~ '^[0-9]+\.[0-9]+(\.[0-9]+)?$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS extension_update_pins (
    extension_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(extension_id,scope,scope_id),
    FOREIGN KEY(extension_id,version) REFERENCES extension_registry_versions(extension_id,version) ON DELETE RESTRICT,
    CONSTRAINT extension_update_pins_scope_02011 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(scope_id)>0)),
    CONSTRAINT extension_update_pins_version_02011 CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$')
);
CREATE INDEX IF NOT EXISTS idx_extension_update_pins_scope_02011 ON extension_update_pins(scope,scope_id);

CREATE TABLE IF NOT EXISTS extension_update_leases (
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(scope,scope_id),
    CONSTRAINT extension_update_leases_scope_02011 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(scope_id)>0)),
    CONSTRAINT extension_update_leases_owner_02011 CHECK (length(owner) BETWEEN 16 AND 256)
);
CREATE INDEX IF NOT EXISTS idx_extension_update_leases_expiry_02011 ON extension_update_leases(expires_at);

CREATE TABLE IF NOT EXISTS extension_update_transactions (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    plan JSONB NOT NULL,
    applied JSONB NOT NULL DEFAULT '[]'::jsonb,
    in_flight TEXT NOT NULL DEFAULT '',
    rolled_back JSONB NOT NULL DEFAULT '[]'::jsonb,
    failure TEXT NOT NULL DEFAULT '',
    lease_owner TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    CONSTRAINT extension_update_transactions_scope_02011 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(scope_id)>0)),
    CONSTRAINT extension_update_transactions_status_02011 CHECK (status IN ('running','succeeded','rolled_back','rollback_failed','failed')),
    CONSTRAINT extension_update_transactions_plan_02011 CHECK (jsonb_typeof(plan)='object'),
    CONSTRAINT extension_update_transactions_applied_02011 CHECK (jsonb_typeof(applied)='array'),
    CONSTRAINT extension_update_transactions_rolled_02011 CHECK (jsonb_typeof(rolled_back)='array')
);
CREATE INDEX IF NOT EXISTS idx_extension_update_transactions_scope_02011 ON extension_update_transactions(scope,scope_id,started_at DESC);
CREATE INDEX IF NOT EXISTS idx_extension_update_transactions_status_02011 ON extension_update_transactions(status,started_at DESC);

COMMENT ON TABLE extension_update_pins IS 'NeverExtensions exact scoped version pins (0.20.11).';
COMMENT ON TABLE extension_update_leases IS 'Cross-replica update lease preventing overlapping multi-extension updates in one scope.';
COMMENT ON TABLE extension_update_transactions IS 'Durable compensation-backed multi-extension update transaction journal.';

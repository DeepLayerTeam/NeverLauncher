-- NeverLauncher 0.20.1: канонический NeverExtensions ядро хранение.
-- Этот миграция добавляет нормализован рабочий модель используется через 
-- канонический neverlauncher-расширение.JSON манифест. Нет registry/runtime
-- поведение является implied здесь; таблица являются авторитетный хранение для
-- расширение идентичность, неизменяемый версии, dependency/permission метаданные и
-- установка состояние.

CREATE TABLE IF NOT EXISTS extensions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    publisher TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    homepage TEXT NOT NULL DEFAULT '',
    repository TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT extensions_id_0201 CHECK (id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'),
    CONSTRAINT extensions_name_0201 CHECK (length(btrim(name)) BETWEEN 1 AND 160),
    CONSTRAINT extensions_publisher_0201 CHECK (length(btrim(publisher)) BETWEEN 1 AND 160)
);

CREATE TABLE IF NOT EXISTS extension_versions (
    extension_id TEXT NOT NULL REFERENCES extensions(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    api TEXT NOT NULL,
    manifest JSONB NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, version),
    CONSTRAINT extension_versions_version_0201 CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'),
    CONSTRAINT extension_versions_schema_0201 CHECK (schema_version = '2.0'),
    CONSTRAINT extension_versions_manifest_0201 CHECK (jsonb_typeof(manifest) = 'object'),
    CONSTRAINT extension_versions_sha256_0201 CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS extension_permissions (
    extension_id TEXT NOT NULL,
    version TEXT NOT NULL,
    permission TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, version, permission),
    FOREIGN KEY (extension_id, version) REFERENCES extension_versions(extension_id, version) ON DELETE CASCADE,
    CONSTRAINT extension_permissions_name_0201 CHECK (permission ~ '^[a-z0-9][a-z0-9._:-]{1,127}$')
);

CREATE TABLE IF NOT EXISTS extension_dependencies (
    extension_id TEXT NOT NULL,
    version TEXT NOT NULL,
    dependency_id TEXT NOT NULL,
    version_constraint TEXT NOT NULL,
    optional BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, version, dependency_id),
    FOREIGN KEY (extension_id, version) REFERENCES extension_versions(extension_id, version) ON DELETE CASCADE,
    CONSTRAINT extension_dependencies_id_0201 CHECK (dependency_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'),
    CONSTRAINT extension_dependencies_self_0201 CHECK (extension_id <> dependency_id),
    CONSTRAINT extension_dependencies_constraint_0201 CHECK (length(btrim(version_constraint)) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS extension_installs (
    extension_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    scope_id TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    source TEXT NOT NULL DEFAULT 'local',
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, scope, scope_id),
    FOREIGN KEY (extension_id, version) REFERENCES extension_versions(extension_id, version) ON DELETE RESTRICT,
    CONSTRAINT extension_installs_scope_0201 CHECK (scope IN ('global','project')),
    CONSTRAINT extension_installs_scope_id_0201 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(btrim(scope_id)) > 0))
);

CREATE INDEX IF NOT EXISTS idx_extension_versions_created_0201
    ON extension_versions(extension_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_extension_permissions_permission_0201
    ON extension_permissions(permission, extension_id, version);
CREATE INDEX IF NOT EXISTS idx_extension_dependencies_dependency_0201
    ON extension_dependencies(dependency_id, extension_id, version);
CREATE INDEX IF NOT EXISTS idx_extension_installs_version_0201
    ON extension_installs(extension_id, version);
CREATE INDEX IF NOT EXISTS idx_extension_installs_enabled_0201
    ON extension_installs(scope, scope_id, extension_id)
    WHERE enabled;

COMMENT ON TABLE extensions IS 'NeverExtensions canonical extension identities (0.20.1).';
COMMENT ON TABLE extension_versions IS 'Immutable canonical neverlauncher-extension.json versions with SHA-256 digest.';
COMMENT ON TABLE extension_permissions IS 'Normalized requested permissions for one immutable extension version.';
COMMENT ON TABLE extension_dependencies IS 'Normalized extension dependencies for one immutable extension version.';
COMMENT ON TABLE extension_installs IS 'Persisted desired install selection; lifecycle activation is introduced by later NeverExtensions releases.';

CREATE OR REPLACE FUNCTION neverlauncher_extension_identity_guard_0201()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.publisher IS DISTINCT FROM OLD.publisher THEN
        RAISE EXCEPTION 'NeverExtensions identity id/publisher is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_extensions_identity_guard_0201 ON extensions;
CREATE TRIGGER trg_extensions_identity_guard_0201
BEFORE UPDATE ON extensions
FOR EACH ROW EXECUTE FUNCTION neverlauncher_extension_identity_guard_0201();

CREATE OR REPLACE FUNCTION neverlauncher_extension_version_guard_0201()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.extension_id IS DISTINCT FROM OLD.extension_id
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
       OR NEW.api IS DISTINCT FROM OLD.api
       OR NEW.manifest IS DISTINCT FROM OLD.manifest
       OR NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'NeverExtensions extension version is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_extension_versions_immutable_0201 ON extension_versions;
CREATE TRIGGER trg_extension_versions_immutable_0201
BEFORE UPDATE ON extension_versions
FOR EACH ROW EXECUTE FUNCTION neverlauncher_extension_version_guard_0201();

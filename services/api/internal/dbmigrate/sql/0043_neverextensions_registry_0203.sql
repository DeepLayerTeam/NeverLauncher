-- NeverLauncher 0.20.3: production NeverExtensions private/local registry.
-- Registry metadata is normalized around immutable extension versions and
-- content-addressed signed .nlext artifacts. Mutable state is intentionally
-- limited to publisher/key activation, channel pointers and yank metadata.

CREATE TABLE IF NOT EXISTS extension_registry_publishers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT extension_registry_publishers_id_0203 CHECK (id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'),
    CONSTRAINT extension_registry_publishers_name_0203 CHECK (length(btrim(name)) BETWEEN 1 AND 160)
);

CREATE TABLE IF NOT EXISTS extension_registry_publisher_keys (
    publisher_id TEXT NOT NULL REFERENCES extension_registry_publishers(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'Ed25519',
    public_key_base64 TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (publisher_id, fingerprint),
    CONSTRAINT extension_registry_publisher_keys_fingerprint_0203 CHECK (fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT extension_registry_publisher_keys_algorithm_0203 CHECK (algorithm = 'Ed25519'),
    CONSTRAINT extension_registry_publisher_keys_public_key_0203 CHECK (length(public_key_base64) BETWEEN 40 AND 128),
    CONSTRAINT extension_registry_publisher_keys_state_0203 CHECK ((active AND revoked_at IS NULL) OR (NOT active))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_extension_registry_key_fingerprint_0203
    ON extension_registry_publisher_keys(fingerprint);

CREATE TABLE IF NOT EXISTS extension_registry_versions (
    extension_id TEXT NOT NULL,
    version TEXT NOT NULL,
    publisher_id TEXT NOT NULL REFERENCES extension_registry_publishers(id) ON DELETE RESTRICT,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    yanked_at TIMESTAMPTZ,
    yank_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (extension_id, version),
    FOREIGN KEY (extension_id, version) REFERENCES extension_versions(extension_id, version) ON DELETE RESTRICT,
    CONSTRAINT extension_registry_versions_yank_0203 CHECK ((yanked_at IS NULL AND yank_reason='') OR (yanked_at IS NOT NULL AND length(btrim(yank_reason)) BETWEEN 1 AND 500))
);

CREATE TABLE IF NOT EXISTS extension_registry_compatibility (
    extension_id TEXT NOT NULL,
    version TEXT NOT NULL,
    min_neverlauncher TEXT NOT NULL DEFAULT '',
    max_neverlauncher TEXT NOT NULL DEFAULT '',
    supported_os JSONB NOT NULL DEFAULT '[]'::jsonb,
    supported_architectures JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (extension_id, version),
    FOREIGN KEY (extension_id, version) REFERENCES extension_registry_versions(extension_id, version) ON DELETE CASCADE,
    CONSTRAINT extension_registry_compatibility_min_0203 CHECK (min_neverlauncher='' OR min_neverlauncher ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'),
    CONSTRAINT extension_registry_compatibility_max_0203 CHECK (max_neverlauncher='' OR max_neverlauncher ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'),
    CONSTRAINT extension_registry_compatibility_os_0203 CHECK (jsonb_typeof(supported_os)='array'),
    CONSTRAINT extension_registry_compatibility_arch_0203 CHECK (jsonb_typeof(supported_architectures)='array')
);

CREATE TABLE IF NOT EXISTS extension_registry_artifacts (
    package_identity TEXT PRIMARY KEY,
    extension_id TEXT NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    storage_project TEXT NOT NULL,
    storage_version TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    signature_key_fingerprint TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (extension_id, version),
    FOREIGN KEY (extension_id, version) REFERENCES extension_registry_versions(extension_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (signature_key_fingerprint) REFERENCES extension_registry_publisher_keys(fingerprint) ON DELETE RESTRICT,
    CONSTRAINT extension_registry_artifacts_identity_0203 CHECK (package_identity ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT extension_registry_artifacts_sha256_0203 CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT extension_registry_artifacts_size_0203 CHECK (size_bytes > 0),
    CONSTRAINT extension_registry_artifacts_storage_project_0203 CHECK (length(btrim(storage_project)) BETWEEN 1 AND 160),
    CONSTRAINT extension_registry_artifacts_storage_version_0203 CHECK (length(btrim(storage_version)) BETWEEN 1 AND 255),
    CONSTRAINT extension_registry_artifacts_storage_path_0203 CHECK (length(btrim(storage_path)) BETWEEN 1 AND 1024)
);

CREATE TABLE IF NOT EXISTS extension_registry_channels (
    extension_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (extension_id, channel),
    FOREIGN KEY (extension_id, version) REFERENCES extension_registry_versions(extension_id, version) ON DELETE RESTRICT,
    CONSTRAINT extension_registry_channels_name_0203 CHECK (channel ~ '^[a-z0-9][a-z0-9._-]{1,63}$')
);

CREATE INDEX IF NOT EXISTS idx_extension_registry_versions_published_0203
    ON extension_registry_versions(extension_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_extension_registry_versions_active_0203
    ON extension_registry_versions(extension_id, published_at DESC) WHERE yanked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_extension_registry_channels_version_0203
    ON extension_registry_channels(extension_id, version);
CREATE INDEX IF NOT EXISTS idx_extension_registry_artifacts_sha256_0203
    ON extension_registry_artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_extension_registry_publishers_active_0203
    ON extension_registry_publishers(id) WHERE active;

CREATE OR REPLACE FUNCTION neverlauncher_registry_version_guard_0203()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE manifest_publisher TEXT;
BEGIN
    IF TG_OP='INSERT' THEN
        SELECT manifest->>'publisher' INTO manifest_publisher
          FROM extension_versions WHERE extension_id=NEW.extension_id AND version=NEW.version;
        IF manifest_publisher IS NULL OR manifest_publisher <> NEW.publisher_id THEN
            RAISE EXCEPTION 'registry publisher % does not own manifest publisher %', NEW.publisher_id, manifest_publisher;
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.extension_id IS DISTINCT FROM OLD.extension_id
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.publisher_id IS DISTINCT FROM OLD.publisher_id
       OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
        RAISE EXCEPTION 'NeverExtensions registry publication identity is immutable';
    END IF;
    IF OLD.yanked_at IS NOT NULL AND (NEW.yanked_at IS NULL OR NEW.yank_reason IS DISTINCT FROM OLD.yank_reason) THEN
        RAISE EXCEPTION 'NeverExtensions yank state is irreversible';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_extension_registry_versions_guard_0203 ON extension_registry_versions;
CREATE TRIGGER trg_extension_registry_versions_guard_0203
BEFORE INSERT OR UPDATE ON extension_registry_versions
FOR EACH ROW EXECUTE FUNCTION neverlauncher_registry_version_guard_0203();

CREATE OR REPLACE FUNCTION neverlauncher_registry_immutable_guard_0203()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'NeverExtensions registry artifact/compatibility rows are immutable';
END;
$$;
DROP TRIGGER IF EXISTS trg_extension_registry_artifacts_immutable_0203 ON extension_registry_artifacts;
CREATE TRIGGER trg_extension_registry_artifacts_immutable_0203
BEFORE UPDATE OR DELETE ON extension_registry_artifacts
FOR EACH ROW EXECUTE FUNCTION neverlauncher_registry_immutable_guard_0203();
DROP TRIGGER IF EXISTS trg_extension_registry_compatibility_immutable_0203 ON extension_registry_compatibility;
CREATE TRIGGER trg_extension_registry_compatibility_immutable_0203
BEFORE UPDATE OR DELETE ON extension_registry_compatibility
FOR EACH ROW EXECUTE FUNCTION neverlauncher_registry_immutable_guard_0203();

CREATE OR REPLACE FUNCTION neverlauncher_registry_channel_guard_0203()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM extension_registry_versions WHERE extension_id=NEW.extension_id AND version=NEW.version AND yanked_at IS NOT NULL) THEN
        RAISE EXCEPTION 'channel cannot point to yanked NeverExtensions version';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_extension_registry_channels_guard_0203 ON extension_registry_channels;
CREATE TRIGGER trg_extension_registry_channels_guard_0203
BEFORE INSERT OR UPDATE ON extension_registry_channels
FOR EACH ROW EXECUTE FUNCTION neverlauncher_registry_channel_guard_0203();

COMMENT ON TABLE extension_registry_publishers IS 'NeverExtensions private/local registry publisher identities (0.20.3).';
COMMENT ON TABLE extension_registry_publisher_keys IS 'Trusted Ed25519 publisher keys used to verify signed .nlext artifacts.';
COMMENT ON TABLE extension_registry_versions IS 'Published immutable extension versions with irreversible yank state.';
COMMENT ON TABLE extension_registry_compatibility IS 'Immutable NeverLauncher/platform compatibility metadata for published versions.';
COMMENT ON TABLE extension_registry_artifacts IS 'Content-addressed verified .nlext artifact metadata; bytes live in configured NeverLauncher storage.';
COMMENT ON TABLE extension_registry_channels IS 'Mutable registry channel pointers such as stable/beta/dev.';

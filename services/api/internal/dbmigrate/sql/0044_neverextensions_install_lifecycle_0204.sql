-- NeverLauncher 0.20.4: рабочий NeverExtensions установка жизненный цикл.
-- Существующий 0.20.1/0.20.3 установка строки представленный desired метаданные только;
-- они являются мигрировать к desired=disabled/current=отсутствующий потому что нет полезная нагрузка имел
-- ever был staged/activated на диск до этот релиз.

ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS desired_version TEXT;
UPDATE extension_installs SET desired_version=version WHERE desired_version IS NULL OR desired_version='';
ALTER TABLE extension_installs ALTER COLUMN desired_version SET NOT NULL;

ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS current_version TEXT NOT NULL DEFAULT '';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS desired_state TEXT NOT NULL DEFAULT 'disabled';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS current_state TEXT NOT NULL DEFAULT 'absent';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS package_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS current_package_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS previous_version TEXT NOT NULL DEFAULT '';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS previous_package_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE extension_installs ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;

UPDATE extension_installs
SET desired_state=CASE WHEN enabled THEN 'enabled' ELSE 'disabled' END,
    current_state='absent',
    current_version='',
    current_package_identity='',
    package_identity=CASE
      WHEN source LIKE 'registry:%#sha256:%' THEN substring(source from '(sha256:[0-9a-f]{64})$')
      ELSE package_identity
    END,
    generation=0,
    activated_at=NULL;

ALTER TABLE extension_installs DROP CONSTRAINT IF EXISTS extension_installs_desired_state_0204;
ALTER TABLE extension_installs ADD CONSTRAINT extension_installs_desired_state_0204
    CHECK (desired_state IN ('absent','disabled','enabled','error'));
ALTER TABLE extension_installs DROP CONSTRAINT IF EXISTS extension_installs_current_state_0204;
ALTER TABLE extension_installs ADD CONSTRAINT extension_installs_current_state_0204
    CHECK (current_state IN ('absent','disabled','enabled','error'));
ALTER TABLE extension_installs DROP CONSTRAINT IF EXISTS extension_installs_generation_0204;
ALTER TABLE extension_installs ADD CONSTRAINT extension_installs_generation_0204 CHECK (generation >= 0);
ALTER TABLE extension_installs DROP CONSTRAINT IF EXISTS extension_installs_desired_version_alias_0204;
ALTER TABLE extension_installs ADD CONSTRAINT extension_installs_desired_version_alias_0204 CHECK (version=desired_version);
ALTER TABLE extension_installs DROP CONSTRAINT IF EXISTS extension_installs_package_identity_0204;
ALTER TABLE extension_installs ADD CONSTRAINT extension_installs_package_identity_0204
    CHECK (package_identity='' OR package_identity ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE extension_installs DROP CONSTRAINT IF EXISTS extension_installs_current_package_identity_0204;
ALTER TABLE extension_installs ADD CONSTRAINT extension_installs_current_package_identity_0204
    CHECK (current_package_identity='' OR current_package_identity ~ '^sha256:[0-9a-f]{64}$');

CREATE TABLE IF NOT EXISTS extension_install_revisions (
    id BIGSERIAL PRIMARY KEY,
    extension_id TEXT NOT NULL REFERENCES extensions(id) ON DELETE RESTRICT,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    generation BIGINT NOT NULL,
    operation TEXT NOT NULL,
    from_version TEXT NOT NULL DEFAULT '',
    to_version TEXT NOT NULL DEFAULT '',
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    from_package_identity TEXT NOT NULL DEFAULT '',
    to_package_identity TEXT NOT NULL DEFAULT '',
    backup_path TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(extension_id,scope,scope_id,generation),
    CONSTRAINT extension_install_revisions_scope_0204 CHECK (scope IN ('global','project')),
    CONSTRAINT extension_install_revisions_scope_id_0204 CHECK ((scope='global' AND scope_id='') OR (scope='project' AND length(btrim(scope_id)) > 0)),
    CONSTRAINT extension_install_revisions_generation_0204 CHECK (generation > 0),
    CONSTRAINT extension_install_revisions_operation_0204 CHECK (operation IN ('install','enable','disable','update','rollback','uninstall')),
    CONSTRAINT extension_install_revisions_from_state_0204 CHECK (from_state IN ('absent','disabled','enabled','error')),
    CONSTRAINT extension_install_revisions_to_state_0204 CHECK (to_state IN ('absent','disabled','enabled','error')),
    CONSTRAINT extension_install_revisions_from_identity_0204 CHECK (from_package_identity='' OR from_package_identity ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT extension_install_revisions_to_identity_0204 CHECK (to_package_identity='' OR to_package_identity ~ '^sha256:[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS idx_extension_install_revisions_scope_0204
    ON extension_install_revisions(scope,scope_id,extension_id,generation DESC);
CREATE INDEX IF NOT EXISTS idx_extension_install_revisions_backup_0204
    ON extension_install_revisions(extension_id,scope,scope_id,generation DESC)
    WHERE backup_path<>'';

CREATE OR REPLACE FUNCTION neverlauncher_extension_install_state_guard_0204()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.version <> NEW.desired_version THEN
        RAISE EXCEPTION 'extension install version must equal desired_version';
    END IF;
    IF NEW.current_state='absent' AND (NEW.current_version<>'' OR NEW.current_package_identity<>'' OR NEW.enabled) THEN
        RAISE EXCEPTION 'absent extension install cannot have current version/package or enabled=true';
    END IF;
    IF NEW.current_state IN ('disabled','enabled') AND NEW.current_version='' THEN
        RAISE EXCEPTION 'active extension install state requires current_version';
    END IF;
    IF NEW.current_state='enabled' AND NOT NEW.enabled THEN
        RAISE EXCEPTION 'enabled extension install state requires enabled=true';
    END IF;
    IF NEW.current_state<>'enabled' AND NEW.enabled THEN
        RAISE EXCEPTION 'enabled=true requires current_state=enabled';
    END IF;
    IF NEW.current_version<>'' AND NOT EXISTS(
        SELECT 1 FROM extension_versions v WHERE v.extension_id=NEW.extension_id AND v.version=NEW.current_version
    ) THEN
        RAISE EXCEPTION 'current extension version does not exist';
    END IF;
    IF NEW.package_identity<>'' AND NOT EXISTS(
        SELECT 1 FROM extension_registry_artifacts a WHERE a.package_identity=NEW.package_identity AND a.extension_id=NEW.extension_id AND a.version=NEW.desired_version
    ) THEN
        RAISE EXCEPTION 'desired package identity does not match registry artifact';
    END IF;
    IF NEW.current_package_identity<>'' AND NOT EXISTS(
        SELECT 1 FROM extension_registry_artifacts a WHERE a.package_identity=NEW.current_package_identity AND a.extension_id=NEW.extension_id AND a.version=NEW.current_version
    ) THEN
        RAISE EXCEPTION 'current package identity does not match registry artifact';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_extension_installs_state_guard_0204 ON extension_installs;
CREATE TRIGGER trg_extension_installs_state_guard_0204
BEFORE INSERT OR UPDATE ON extension_installs
FOR EACH ROW EXECUTE FUNCTION neverlauncher_extension_install_state_guard_0204();

COMMENT ON TABLE extension_installs IS 'NeverExtensions 0.20.4 persistent desired/current install lifecycle state.';
COMMENT ON TABLE extension_install_revisions IS 'Append-only successful NeverExtensions lifecycle transitions and rollback backup references.';

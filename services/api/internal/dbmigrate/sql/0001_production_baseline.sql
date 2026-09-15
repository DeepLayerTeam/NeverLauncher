-- NeverLauncher 0.10.0-P0 production baseline.
-- This migration is intentionally idempotent and also normalizes the two historical
-- PostgreSQL layouts that shipped before 0.10.0 into the schema used by SQLRepository.

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    homepage TEXT NOT NULL DEFAULT '',
    repository TEXT NOT NULL DEFAULT '',
    default_channel TEXT NOT NULL DEFAULT 'stable',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS homepage TEXT NOT NULL DEFAULT '';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS repository TEXT NOT NULL DEFAULT '';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS default_channel TEXT NOT NULL DEFAULT 'stable';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE projects ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- release_versions must exist before legacy files/channels are normalized.  The old
-- 4.5 schema called this table "versions"; copy every row before removing that table.
CREATE TABLE IF NOT EXISTS release_versions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, profile_id, channel, version)
);
ALTER TABLE release_versions ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft';
ALTER TABLE release_versions ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE release_versions ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;
ALTER TABLE release_versions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE release_versions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
DO $$
BEGIN
    IF to_regclass('versions') IS NOT NULL THEN
        EXECUTE $m$
            INSERT INTO release_versions(id, project_id, profile_id, channel, version, status, manifest, published_at, created_at, updated_at)
            SELECT id,
                   project_id,
                   profile_id,
                   channel,
                   version,
                   COALESCE(NULLIF(status, ''), 'draft'),
                   jsonb_build_object(
                       'schemaVersion', '1.0',
                       'projectId', project_id,
                       'profileId', profile_id,
                       'channel', channel,
                       'version', version,
                       'createdAt', COALESCE(published_at, created_at, now()),
                       'files', jsonb_build_array()
                   ),
                   published_at,
                   COALESCE(created_at, now()),
                   now()
            FROM versions
            ON CONFLICT(project_id, profile_id, channel, version) DO UPDATE
            SET status = EXCLUDED.status,
                published_at = COALESCE(release_versions.published_at, EXCLUDED.published_at),
                updated_at = now()
        $m$;
    END IF;
END $$;

-- Historical 4.5 release_channels had profile_id/channel/current_version_id columns
-- with NOT NULL constraints that make current SQLRepository inserts fail.  Rebuild it
-- into the canonical (project_id,id) layout while preserving channel data.
CREATE TABLE IF NOT EXISTS release_channels (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    protected BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY(project_id, id)
);
ALTER TABLE release_channels ADD COLUMN IF NOT EXISTS id TEXT;
ALTER TABLE release_channels ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE release_channels ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE release_channels ADD COLUMN IF NOT EXISTS protected BOOLEAN NOT NULL DEFAULT false;
DROP TABLE IF EXISTS _nl_p0_release_channels;
CREATE TABLE _nl_p0_release_channels (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    protected BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY(project_id, id)
);
DO $$
DECLARE has_channel BOOLEAN;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'release_channels' AND column_name = 'channel'
    ) INTO has_channel;
    IF has_channel THEN
        EXECUTE $m$
            INSERT INTO _nl_p0_release_channels(id, project_id, name, description, protected)
            SELECT COALESCE(NULLIF(id, ''), channel),
                   project_id,
                   COALESCE(NULLIF(name, ''), channel),
                   COALESCE(description, ''),
                   COALESCE(protected, false)
            FROM release_channels
            WHERE project_id IS NOT NULL AND COALESCE(NULLIF(id, ''), NULLIF(channel, '')) IS NOT NULL
            ON CONFLICT(project_id, id) DO UPDATE
            SET name = EXCLUDED.name, description = EXCLUDED.description, protected = EXCLUDED.protected
        $m$;
    ELSE
        INSERT INTO _nl_p0_release_channels(id, project_id, name, description, protected)
        SELECT id, project_id, COALESCE(NULLIF(name, ''), id), COALESCE(description, ''), COALESCE(protected, false)
        FROM release_channels
        WHERE project_id IS NOT NULL AND NULLIF(id, '') IS NOT NULL
        ON CONFLICT(project_id, id) DO UPDATE
        SET name = EXCLUDED.name, description = EXCLUDED.description, protected = EXCLUDED.protected;
    END IF;

    IF to_regclass('release_channels_v52') IS NOT NULL THEN
        EXECUTE $m$
            INSERT INTO _nl_p0_release_channels(id, project_id, name, description, protected)
            SELECT id, project_id, COALESCE(NULLIF(name, ''), id), COALESCE(description, ''), COALESCE(protected, false)
            FROM release_channels_v52
            WHERE project_id IS NOT NULL AND NULLIF(id, '') IS NOT NULL
            ON CONFLICT(project_id, id) DO UPDATE
            SET name = EXCLUDED.name, description = EXCLUDED.description, protected = EXCLUDED.protected
        $m$;
    END IF;
END $$;
DROP TABLE release_channels;
ALTER TABLE _nl_p0_release_channels RENAME TO release_channels;
DROP TABLE IF EXISTS release_channels_v52;

-- Normalize files.  The 4.5 layout referenced "versions" and storage_objects and had
-- mandatory storage_object_id; current repository stores immutable file metadata on
-- the files row itself.  Refuse the migration rather than silently dropping orphans.
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES release_versions(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    required BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(version_id, path)
);
ALTER TABLE files ADD COLUMN IF NOT EXISTS id TEXT;
ALTER TABLE files ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE files ADD COLUMN IF NOT EXISTS size BIGINT NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE files ADD COLUMN IF NOT EXISTS url TEXT NOT NULL DEFAULT '';
ALTER TABLE files ADD COLUMN IF NOT EXISTS required BOOLEAN NOT NULL DEFAULT true;
UPDATE files SET id = 'file-' || md5(version_id || ':' || path) WHERE id IS NULL OR id = '';
UPDATE files f SET project_id = rv.project_id FROM release_versions rv
WHERE (f.project_id IS NULL OR f.project_id = '') AND f.version_id = rv.id;
DO $$
DECLARE has_storage_object BOOLEAN; has_size_bytes BOOLEAN;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='files' AND column_name='storage_object_id'
    ) INTO has_storage_object;
    SELECT EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='storage_objects' AND column_name='size_bytes'
    ) INTO has_size_bytes;
    IF has_storage_object AND to_regclass('storage_objects') IS NOT NULL THEN
        IF has_size_bytes THEN
            EXECUTE $m$
                UPDATE files f SET
                    size = CASE WHEN f.size = 0 THEN COALESCE(o.size_bytes, 0) ELSE f.size END,
                    sha256 = CASE WHEN f.sha256 = '' THEN COALESCE(o.sha256, '') ELSE f.sha256 END
                FROM storage_objects o WHERE f.storage_object_id = o.id
            $m$;
        ELSE
            EXECUTE $m$
                UPDATE files f SET
                    size = CASE WHEN f.size = 0 THEN COALESCE(o.size, 0) ELSE f.size END,
                    sha256 = CASE WHEN f.sha256 = '' THEN COALESCE(o.sha256, '') ELSE f.sha256 END,
                    url = CASE WHEN f.url = '' THEN COALESCE(o.url, '') ELSE f.url END
                FROM storage_objects o WHERE f.storage_object_id = o.id
            $m$;
        END IF;
    END IF;
END $$;
DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken
    FROM files f LEFT JOIN release_versions rv ON rv.id = f.version_id
    WHERE f.id IS NULL OR f.id = '' OR f.project_id IS NULL OR f.project_id = '' OR rv.id IS NULL;
    IF broken > 0 THEN
        RAISE EXCEPTION 'P0 migration refused: % file rows cannot be mapped to release_versions', broken;
    END IF;
END $$;
DROP TABLE IF EXISTS _nl_p0_files;
CREATE TABLE _nl_p0_files (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES release_versions(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    required BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(version_id, path)
);
INSERT INTO _nl_p0_files(id, project_id, version_id, path, size, sha256, url, required)
SELECT id, project_id, version_id, path, COALESCE(size,0), COALESCE(sha256,''), COALESCE(url,''), COALESCE(required,true)
FROM files;
DROP TABLE files;
ALTER TABLE _nl_p0_files RENAME TO files;

-- The old "versions" table now has no consumers; removing it is necessary before
-- rebuilding profiles because it carries a foreign key to the historical profile table.
DROP TABLE IF EXISTS versions;

-- Normalize profiles so obsolete NOT NULL title/minecraft_version columns cannot break
-- current SaveProfile inserts.
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    loader TEXT NOT NULL DEFAULT 'vanilla',
    preset TEXT NOT NULL DEFAULT '',
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(project_id, id)
);
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS loader TEXT NOT NULL DEFAULT 'vanilla';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS preset TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
DO $$
BEGIN
    IF EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='profiles' AND column_name='title'
    ) THEN
        EXECUTE $m$UPDATE profiles SET name = title WHERE (name IS NULL OR name = '') AND title IS NOT NULL$m$;
    END IF;
END $$;
DROP TABLE IF EXISTS _nl_p0_profiles;
CREATE TABLE _nl_p0_profiles (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    loader TEXT NOT NULL DEFAULT 'vanilla',
    preset TEXT NOT NULL DEFAULT '',
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(project_id, id)
);
INSERT INTO _nl_p0_profiles(id, project_id, name, description, loader, preset, is_default, created_at, updated_at)
SELECT id, project_id, COALESCE(NULLIF(name,''), id), COALESCE(description,''), COALESCE(NULLIF(loader,''),'vanilla'), COALESCE(preset,''), COALESCE(is_default,false), COALESCE(created_at,now()), COALESCE(updated_at,now())
FROM profiles;
DROP TABLE profiles;
ALTER TABLE _nl_p0_profiles RENAME TO profiles;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role_id TEXT NOT NULL DEFAULT 'viewer',
    status TEXT NOT NULL DEFAULT 'active',
    project_roles JSONB NOT NULL DEFAULT '{}'::jsonb,
    password_hash TEXT NOT NULL DEFAULT '',
    password_updated_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id TEXT NOT NULL DEFAULT 'viewer';
ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS project_roles JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb
);
ALTER TABLE roles ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE roles ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb;
INSERT INTO roles(id,name,description,permissions) VALUES
 ('owner','Владелец','Полный доступ','["*"]'::jsonb),
 ('admin','Администратор','Администрирование платформы','["project:read","project:write","release:prepare","release:publish","file:write","users:manage","roles:manage","audit:read","diagnostics:read","storage:manage","settings:manage","security:read","extension:manage"]'::jsonb),
 ('release-manager','Release Manager','Управление релизами','["project:read","release:prepare","release:publish","audit:read"]'::jsonb),
 ('developer','Разработчик','Подготовка версий','["project:read","release:prepare","file:write"]'::jsonb),
 ('viewer','Наблюдатель','Только чтение','["project:read"]'::jsonb),
 ('player','Игрок','Desktop launcher','["launcher:login","profile:download","profile:launch"]'::jsonb)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, permissions=EXCLUDED.permissions;

-- Audit table also had an incompatible 4.5 layout (actor_id/event/payload).  Keep the
-- old columns for forensic compatibility but add/fill the columns used by SQLRepository.
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS target TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';
DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='audit_events' AND column_name='event') THEN
        EXECUTE $m$UPDATE audit_events SET action = event WHERE action = '' AND event IS NOT NULL$m$;
    END IF;
    IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='audit_events' AND column_name='actor_id') THEN
        EXECUTE $m$UPDATE audit_events SET actor = actor_id WHERE actor = '' AND actor_id IS NOT NULL$m$;
    END IF;
END $$;
DROP TABLE IF EXISTS _nl_p0_audit_events;
CREATE TABLE _nl_p0_audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO _nl_p0_audit_events(id,actor,action,target,ip,user_agent,created_at)
SELECT id, COALESCE(actor,''), COALESCE(action,''), COALESCE(target,''), COALESCE(ip,''), COALESCE(user_agent,''), COALESCE(created_at,now())
FROM audit_events;
DROP TABLE audit_events;
ALTER TABLE _nl_p0_audit_events RENAME TO audit_events;

CREATE TABLE IF NOT EXISTS telemetry_events (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL DEFAULT '', profile_id TEXT, launcher_version TEXT,
    profile_version TEXT, event TEXT NOT NULL, status TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS crash_reports (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL DEFAULT '', profile_id TEXT, launcher_version TEXT,
    profile_version TEXT, message TEXT NOT NULL, log TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
-- Rebuild to remove obsolete mandatory columns such as the historical "status" field.
DROP TABLE IF EXISTS _nl_p0_admin_sessions;
CREATE TABLE _nl_p0_admin_sessions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);
INSERT INTO _nl_p0_admin_sessions(id,user_id,token_hash,expires_at,created_at,revoked_at)
SELECT id,user_id,COALESCE(token_hash,''),COALESCE(expires_at,COALESCE(created_at,now())),COALESCE(created_at,now()),revoked_at
FROM admin_sessions;
DROP TABLE admin_sessions;
ALTER TABLE _nl_p0_admin_sessions RENAME TO admin_sessions;
CREATE TABLE IF NOT EXISTS project_user_roles (
    project_id TEXT NOT NULL, user_id TEXT NOT NULL, role_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(project_id,user_id)
);
ALTER TABLE project_user_roles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS storage_objects (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', size BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', storage_driver TEXT NOT NULL DEFAULT 'local',
    storage_key TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS size BIGINT NOT NULL DEFAULT 0;
ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS url TEXT NOT NULL DEFAULT '';
ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS storage_driver TEXT NOT NULL DEFAULT 'local';
ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS storage_key TEXT NOT NULL DEFAULT '';
DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='storage_objects' AND column_name='size_bytes') THEN
        EXECUTE $m$UPDATE storage_objects SET size = size_bytes WHERE size = 0 AND size_bytes IS NOT NULL$m$;
    END IF;
END $$;
DROP TABLE IF EXISTS storage_objects_v52;

CREATE TABLE IF NOT EXISTS neverlauncher_persistence_snapshots_950 (
    id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL, schema_version TEXT NOT NULL,
    payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_profiles_project_id_p0 ON profiles(project_id);
CREATE INDEX IF NOT EXISTS idx_release_channels_project_p0 ON release_channels(project_id,id);
CREATE INDEX IF NOT EXISTS idx_release_versions_lookup_p0 ON release_versions(project_id,profile_id,channel,version);
CREATE INDEX IF NOT EXISTS idx_files_project_version_p0 ON files(project_id,version_id);
CREATE INDEX IF NOT EXISTS idx_users_email_lower_p0 ON users(lower(email));
CREATE INDEX IF NOT EXISTS idx_audit_events_created_p0 ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_created_p0 ON telemetry_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_crash_reports_created_p0 ON crash_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_persistence_kind_created_p0 ON neverlauncher_persistence_snapshots_950(kind,created_at DESC);

-- NeverLauncher 0.14.1 — ServerBridge Protocol v2 + PostgreSQL source of truth.
-- ServerBridge state is normalized and durable. Join authorizations are one-time
-- tickets: exactly one validator may atomically consume an active, unexpired row.

CREATE TABLE IF NOT EXISTS server_bridge_nodes_v2 (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'velocity',
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    protocol_version INTEGER NOT NULL DEFAULT 2,
    plugin_version TEXT NOT NULL DEFAULT '',
    plugin_sha256 TEXT NOT NULL DEFAULT '',
    integrity_status TEXT NOT NULL DEFAULT '',
    integrity_verified_at TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    CONSTRAINT server_bridge_nodes_v2_protocol_check CHECK (protocol_version = 2),
    CONSTRAINT server_bridge_nodes_v2_kind_check CHECK (kind IN ('velocity','paper','purpur')),
    CONSTRAINT server_bridge_nodes_v2_status_check CHECK (status IN ('active','disabled','credential-rotation-required')),
    CONSTRAINT server_bridge_nodes_v2_token_hash_check CHECK (token_hash = '' OR token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT server_bridge_nodes_v2_plugin_hash_check CHECK (plugin_sha256 = '' OR plugin_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_v2_project ON server_bridge_nodes_v2(project_id,status,id);
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_v2_heartbeat ON server_bridge_nodes_v2(last_heartbeat_at DESC) WHERE status='active';

CREATE TABLE IF NOT EXISTS server_bridge_join_tickets_v2 (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    username_normalized TEXT NOT NULL,
    player_uuid TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'stable',
    access_token_hash TEXT NOT NULL,
    trusted_device_id TEXT REFERENCES trusted_devices(id),
    binding_epoch BIGINT NOT NULL DEFAULT 1,
    minecraft_session_id TEXT REFERENCES minecraft_sessions(id) ON DELETE CASCADE,
    protocol_version INTEGER NOT NULL DEFAULT 2,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    CONSTRAINT server_bridge_join_v2_protocol_check CHECK (protocol_version = 2),
    CONSTRAINT server_bridge_join_v2_status_check CHECK (status IN ('active','consumed','invalidated','replaced')),
    CONSTRAINT server_bridge_join_v2_username_check CHECK (username ~ '^[A-Za-z0-9_]{3,16}$'),
    CONSTRAINT server_bridge_join_v2_username_normalized_check CHECK (username_normalized = lower(username)),
    CONSTRAINT server_bridge_join_v2_binding_epoch_check CHECK (binding_epoch >= 1),
    CONSTRAINT server_bridge_join_v2_access_hash_check CHECK (access_token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT server_bridge_join_v2_expiry_check CHECK (expires_at > created_at AND expires_at <= created_at + interval '2 minutes 5 seconds'),
    CONSTRAINT server_bridge_join_v2_terminal_check CHECK (
        (status='active' AND consumed_at IS NULL AND invalidated_at IS NULL) OR
        (status='consumed' AND consumed_at IS NOT NULL AND invalidated_at IS NULL) OR
        (status IN ('invalidated','replaced') AND consumed_at IS NULL AND invalidated_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_server_bridge_join_v2_active_player
    ON server_bridge_join_tickets_v2(server_id,username_normalized) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_v2_session ON server_bridge_join_tickets_v2(session_id,status);
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_v2_user ON server_bridge_join_tickets_v2(user_id,status);
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_v2_expiry ON server_bridge_join_tickets_v2(expires_at) WHERE status='active';

CREATE TABLE IF NOT EXISTS server_bridge_textures_v2 (
    player_uuid TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    skin_url TEXT NOT NULL DEFAULT '',
    cape_url TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT 'classic',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT server_bridge_textures_v2_model_check CHECK (model IN ('classic','slim'))
);

-- Snapshot ServerBridge credentials before 0.14.1 were intentionally excluded
-- from JSON serialization, so they cannot be reconstructed safely. If legacy
-- metadata exists, migrate node identity only and force an administrator token
-- rotation before the node can authenticate. Active legacy joins are not carried
-- across the upgrade because their bearer hash was likewise not persisted.
DO $$
BEGIN
    IF to_regclass('neverlauncher_persistence_snapshots_950') IS NOT NULL THEN
        EXECUTE $m$
            WITH latest AS (
                SELECT payload
                FROM neverlauncher_persistence_snapshots_950
                WHERE kind='all'
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ), legacy AS (
                SELECT e.key AS id, e.value AS v
                FROM latest, LATERAL jsonb_each(COALESCE(payload->'serverBridge'->'servers','{}'::jsonb)) e
            )
            INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,plugin_version,plugin_sha256,integrity_status,integrity_verified_at,created_at,rotated_at)
            SELECT id,
                   COALESCE(NULLIF(v->>'name',''),id),
                   COALESCE(NULLIF(v->>'kind',''),'velocity'),
                   v->>'projectId',
                   COALESCE(v->>'profileId',''),
                   COALESCE(v->>'fingerprint',''),
                   '',
                   COALESCE(v->>'tokenPrefix',''),
                   'credential-rotation-required',
                   2,
                   COALESCE(v->>'pluginVersion',''),
                   CASE WHEN COALESCE(v->>'pluginSha256','') ~ '^[0-9a-f]{64}$' THEN v->>'pluginSha256' ELSE '' END,
                   '',
                   NULL,
                   COALESCE(NULLIF(v->>'createdAt','')::timestamptz,now()),
                   NULLIF(v->>'rotatedAt','')::timestamptz
            FROM legacy
            WHERE COALESCE(v->>'projectId','') <> ''
              AND EXISTS (SELECT 1 FROM projects p WHERE p.id=v->>'projectId')
            ON CONFLICT(id) DO NOTHING
        $m$;

        EXECUTE $m$
            WITH latest AS (
                SELECT payload
                FROM neverlauncher_persistence_snapshots_950
                WHERE kind='all'
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            ), legacy AS (
                SELECT e.key AS uuid, e.value AS v
                FROM latest, LATERAL jsonb_each(COALESCE(payload->'serverBridge'->'textures','{}'::jsonb)) e
            )
            INSERT INTO server_bridge_textures_v2(player_uuid,username,skin_url,cape_url,model,updated_at)
            SELECT uuid,
                   COALESCE(NULLIF(v->>'username',''),uuid),
                   COALESCE(v->>'skinUrl',''),
                   COALESCE(v->>'capeUrl',''),
                   CASE WHEN v->>'model'='slim' THEN 'slim' ELSE 'classic' END,
                   COALESCE(NULLIF(v->>'updatedAt','')::timestamptz,now())
            FROM legacy
            ON CONFLICT(player_uuid) DO NOTHING
        $m$;
    END IF;
END $$;

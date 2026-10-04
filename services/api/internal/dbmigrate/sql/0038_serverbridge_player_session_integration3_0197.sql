-- NeverLauncher 0.19.7: ServerBridge Player Session Integration 3.
-- Correlates launcher -> proxy -> backend gameplay sessions, records ordered
-- transfer hops, prevents active-session cloning and supports topology-wide
-- disconnect through the existing durable Control API.

ALTER TABLE server_bridge_join_tickets_v2
    ADD COLUMN IF NOT EXISTS session_correlation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE server_bridge_join_tickets_v2 DROP CONSTRAINT IF EXISTS server_bridge_join_session_correlation_0197;
ALTER TABLE server_bridge_join_tickets_v2 ADD CONSTRAINT server_bridge_join_session_correlation_0197
    CHECK (session_correlation_id='' OR session_correlation_id ~ '^[0-9a-f]{64}$');
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_session_correlation_0197
    ON server_bridge_join_tickets_v2(session_correlation_id)
    WHERE session_correlation_id<>'';

ALTER TABLE server_bridge_handoffs_v2
    ADD COLUMN IF NOT EXISTS session_correlation_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS transfer_sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE server_bridge_handoffs_v2 DROP CONSTRAINT IF EXISTS server_bridge_handoff_session_correlation_0197;
ALTER TABLE server_bridge_handoffs_v2 ADD CONSTRAINT server_bridge_handoff_session_correlation_0197
    CHECK ((session_correlation_id='' AND transfer_sequence=0) OR (session_correlation_id ~ '^[0-9a-f]{64}$' AND transfer_sequence>0));
CREATE INDEX IF NOT EXISTS idx_server_bridge_handoff_session_correlation_0197
    ON server_bridge_handoffs_v2(session_correlation_id, transfer_sequence)
    WHERE session_correlation_id<>'';

CREATE TABLE IF NOT EXISTS server_bridge_player_sessions_v3 (
    correlation_id CHAR(64) PRIMARY KEY CHECK (correlation_id ~ '^[0-9a-f]{64}$'),
    player_uuid TEXT NOT NULL,
    username TEXT NOT NULL,
    username_normalized TEXT NOT NULL,
    user_id TEXT NOT NULL,
    never_session_id TEXT NOT NULL,
    minecraft_session_id TEXT NOT NULL DEFAULT '',
    trusted_device_id TEXT NOT NULL DEFAULT '',
    binding_epoch BIGINT NOT NULL CHECK (binding_epoch > 0),
    project_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','invalidated','disconnected','expired')),
    proxy_node_id TEXT REFERENCES server_bridge_nodes_v2(id) ON DELETE SET NULL,
    proxy_runtime_id TEXT NOT NULL DEFAULT '',
    proxy_runtime_epoch BIGINT NOT NULL DEFAULT 0 CHECK (proxy_runtime_epoch >= 0),
    backend_node_id TEXT REFERENCES server_bridge_nodes_v2(id) ON DELETE SET NULL,
    backend_runtime_id TEXT NOT NULL DEFAULT '',
    backend_runtime_epoch BIGINT NOT NULL DEFAULT 0 CHECK (backend_runtime_epoch >= 0),
    transfer_sequence BIGINT NOT NULL DEFAULT 0 CHECK (transfer_sequence >= 0),
    recheck_required BOOLEAN NOT NULL DEFAULT FALSE,
    trust_reason TEXT NOT NULL DEFAULT '',
    integrity_reason TEXT NOT NULL DEFAULT '',
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    invalidated_at TIMESTAMPTZ,
    invalidated_reason TEXT NOT NULL DEFAULT '',
    CHECK ((proxy_node_id IS NULL AND proxy_runtime_id='' AND proxy_runtime_epoch=0) OR (proxy_node_id IS NOT NULL AND proxy_runtime_id ~ '^[0-9a-f]{64}$' AND proxy_runtime_epoch>0)),
    CHECK ((backend_node_id IS NULL AND backend_runtime_id='' AND backend_runtime_epoch=0) OR (backend_node_id IS NOT NULL AND backend_runtime_id ~ '^[0-9a-f]{64}$' AND backend_runtime_epoch>0))
);

-- One Never/Minecraft credential may have only one active gameplay correlation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_server_bridge_player_never_session_active_0197
    ON server_bridge_player_sessions_v3(never_session_id, player_uuid)
    WHERE status='active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_server_bridge_player_minecraft_session_active_0197
    ON server_bridge_player_sessions_v3(minecraft_session_id)
    WHERE status='active' AND minecraft_session_id<>'';
CREATE INDEX IF NOT EXISTS idx_server_bridge_player_user_active_0197
    ON server_bridge_player_sessions_v3(user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_server_bridge_player_nodes_active_0197
    ON server_bridge_player_sessions_v3(proxy_node_id, backend_node_id, status)
    WHERE status='active';

CREATE TABLE IF NOT EXISTS server_bridge_player_transfers_v3 (
    correlation_id CHAR(64) NOT NULL REFERENCES server_bridge_player_sessions_v3(correlation_id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    handoff_id TEXT NOT NULL UNIQUE REFERENCES server_bridge_handoffs_v2(id) ON DELETE CASCADE,
    source_node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    source_runtime_id TEXT NOT NULL DEFAULT '',
    source_runtime_epoch BIGINT NOT NULL DEFAULT 0 CHECK (source_runtime_epoch >= 0),
    target_runtime_id TEXT NOT NULL DEFAULT '',
    target_runtime_epoch BIGINT NOT NULL DEFAULT 0 CHECK (target_runtime_epoch >= 0),
    status TEXT NOT NULL DEFAULT 'issued' CHECK (status IN ('issued','consumed','superseded','invalidated','expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (correlation_id, sequence)
);
CREATE INDEX IF NOT EXISTS idx_server_bridge_player_transfers_pending_0197
    ON server_bridge_player_transfers_v3(target_node_id, status, created_at DESC)
    WHERE status='issued';

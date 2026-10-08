-- NeverLauncher 0.14.8: zero-patch topology + one-time proxy -> backend handoff.
-- No Minecraft/proxy configuration table is patched. Topology is learned from
-- authenticated runtime handoffs and PostgreSQL remains the source of truth.

CREATE TABLE IF NOT EXISTS server_bridge_topology_edges_v2 (
    source_node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    backend_name TEXT NOT NULL,
    project_id TEXT NOT NULL,
    profile_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_node_id, target_node_id),
    CHECK (source_node_id <> target_node_id),
    CHECK (btrim(backend_name) <> '')
);

CREATE INDEX IF NOT EXISTS server_bridge_topology_target_idx
    ON server_bridge_topology_edges_v2(target_node_id, status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS server_bridge_handoffs_v2 (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    username_normalized TEXT NOT NULL,
    player_uuid TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    backend_name TEXT NOT NULL,
    project_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    trusted_device_id TEXT,
    binding_epoch BIGINT NOT NULL CHECK (binding_epoch >= 1),
    minecraft_session_id TEXT,
    source_identity_epoch BIGINT NOT NULL CHECK (source_identity_epoch >= 1),
    source_key_fingerprint TEXT NOT NULL CHECK (source_key_fingerprint ~ '^[0-9a-f]{64}$'),
    target_identity_epoch BIGINT NOT NULL CHECK (target_identity_epoch >= 1),
    target_key_fingerprint TEXT NOT NULL CHECK (target_key_fingerprint ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','consumed','replaced','invalidated','expired')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    redeemed_nonce_hash TEXT NOT NULL DEFAULT '',
    redeemed_by_ip TEXT NOT NULL DEFAULT '',
    CHECK (username_normalized = lower(btrim(username))),
    CHECK (source_node_id <> target_node_id),
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS server_bridge_handoffs_active_target_player_uq
    ON server_bridge_handoffs_v2(target_node_id, username_normalized)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS server_bridge_handoffs_source_player_idx
    ON server_bridge_handoffs_v2(source_node_id, username_normalized, created_at DESC);
CREATE INDEX IF NOT EXISTS server_bridge_handoffs_expiry_idx
    ON server_bridge_handoffs_v2(status, expires_at);

COMMENT ON TABLE server_bridge_topology_edges_v2 IS
    '0.14.8 runtime-learned ServerBridge topology; no proxy/server configuration patching';
COMMENT ON TABLE server_bridge_handoffs_v2 IS
    '0.14.8 one-time proxy-to-backend handoffs bound to source and target Ed25519 identity epochs';

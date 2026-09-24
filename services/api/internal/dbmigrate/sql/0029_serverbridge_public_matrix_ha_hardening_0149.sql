-- NeverLauncher 0.14.9: Public ServerBridge Matrix + HA/hardening.
-- Runtime state remains PostgreSQL-native. These indexes support active/active
-- health/freshness queries and bounded advisory-lock maintenance without adding
-- replica-local ownership state.

CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_active_heartbeat_0149
    ON server_bridge_nodes_v2(last_heartbeat_at DESC, id)
    WHERE status='active';

CREATE INDEX IF NOT EXISTS idx_server_bridge_topology_active_freshness_0149
    ON server_bridge_topology_edges_v2(last_seen_at DESC, source_node_id, target_node_id)
    WHERE status='active';

CREATE INDEX IF NOT EXISTS idx_server_bridge_handoffs_active_expiry_0149
    ON server_bridge_handoffs_v2(expires_at, target_node_id)
    WHERE status='active';

CREATE INDEX IF NOT EXISTS idx_server_bridge_join_active_expiry_0149
    ON server_bridge_join_tickets_v2(expires_at, server_id)
    WHERE status='active';

COMMENT ON INDEX idx_server_bridge_nodes_active_heartbeat_0149 IS
    '0.14.9 HA readiness and public/internal ServerBridge freshness queries';
COMMENT ON INDEX idx_server_bridge_topology_active_freshness_0149 IS
    '0.14.9 freshness-aware runtime topology; stale edges are not reported as active';
COMMENT ON INDEX idx_server_bridge_handoffs_active_expiry_0149 IS
    '0.14.9 advisory-lock maintenance for expired one-time handoffs';

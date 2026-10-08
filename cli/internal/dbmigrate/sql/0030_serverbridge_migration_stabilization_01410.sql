-- NeverLauncher 0.14.10: ServerBridge migration + stabilization.
-- This migration keeps the 0.14.1-0.14.9 protocol/data model intact while
-- sealing expired transient rows and adding indexes for the actual 0.14.8+
-- handoff lookup/maintenance paths. No node identities, tickets that are still
-- valid, topology bindings, or release-integrity state are rewritten.

-- Normalize transient rows that may have remained active when 0.14.9 replicas
-- were stopped before their opportunistic maintenance pass ran.
UPDATE server_bridge_join_tickets_v2
SET status='invalidated', invalidated_at=COALESCE(invalidated_at, now())
WHERE status='active' AND expires_at <= now();

UPDATE server_bridge_handoffs_v2
SET status='expired', invalidated_at=COALESCE(invalidated_at, now())
WHERE status='active' AND expires_at <= now();

UPDATE server_bridge_topology_edges_v2
SET status='disabled'
WHERE status='active' AND last_seen_at <= now() - interval '5 minutes';

DELETE FROM server_bridge_node_nonces_v2
WHERE expires_at <= now();

-- Source-proof lookup used when a proxy mints a backend handoff. This avoids a
-- growing sort over the complete ticket history on long-lived installations.
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_consumed_source_01410
    ON server_bridge_join_tickets_v2(server_id, username_normalized, consumed_at DESC)
    WHERE status='consumed';

-- Target resolution accepts a canonical node id or runtime backend name.
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_name_folded_01410
    ON server_bridge_nodes_v2(lower(name), id);

-- Bounded retention cleanup scans terminal rows by age, not by the primary key.
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_terminal_retention_01410
    ON server_bridge_join_tickets_v2(COALESCE(consumed_at, invalidated_at, expires_at), id)
    WHERE status IN ('consumed','invalidated','replaced');

CREATE INDEX IF NOT EXISTS idx_server_bridge_handoff_terminal_retention_01410
    ON server_bridge_handoffs_v2(COALESCE(consumed_at, invalidated_at, expires_at), id)
    WHERE status IN ('consumed','replaced','invalidated','expired');

COMMENT ON INDEX idx_server_bridge_join_consumed_source_01410 IS
    '0.14.10 proxy handoff source-proof lookup for long-lived ServerBridge installations';
COMMENT ON INDEX idx_server_bridge_nodes_name_folded_01410 IS
    '0.14.10 case-insensitive zero-patch backend-name resolution';
COMMENT ON INDEX idx_server_bridge_join_terminal_retention_01410 IS
    '0.14.10 bounded maintenance retention scan for terminal join tickets';
COMMENT ON INDEX idx_server_bridge_handoff_terminal_retention_01410 IS
    '0.14.10 bounded maintenance retention scan for terminal handoffs';

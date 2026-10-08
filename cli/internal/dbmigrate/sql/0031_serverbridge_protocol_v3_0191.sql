-- NeverLauncher 0.19.1 — ServerBridge 3 Protocol v3 rolling-upgrade support.
-- Existing Protocol v2 nodes/tickets stay valid while 0.19.1 nodes negotiate v3.
-- Table names remain *_v2 intentionally: they are durable storage-generation names,
-- not a statement that only wire Protocol v2 is accepted.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_protocol_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_protocol_check
        CHECK (protocol_version IN (2,3));

ALTER TABLE server_bridge_handoffs_v2
    ADD COLUMN IF NOT EXISTS protocol_version SMALLINT NOT NULL DEFAULT 2
        CHECK (protocol_version IN (2,3));

ALTER TABLE server_bridge_join_tickets_v2
    DROP CONSTRAINT IF EXISTS server_bridge_join_v2_protocol_check;
ALTER TABLE server_bridge_join_tickets_v2
    ADD CONSTRAINT server_bridge_join_v2_protocol_check
        CHECK (protocol_version IN (2,3));

COMMENT ON COLUMN server_bridge_nodes_v2.protocol_version IS
    'Negotiated ServerBridge wire protocol. NeverLauncher 0.19.1 accepts v2 and v3; new bridge clients prefer v3.';
COMMENT ON COLUMN server_bridge_join_tickets_v2.protocol_version IS
    'Wire protocol selected for the target ServerBridge node when the one-time ticket was issued.';
COMMENT ON COLUMN server_bridge_handoffs_v2.protocol_version IS
    'Wire protocol selected for the target ServerBridge node when the one-time handoff was issued.';

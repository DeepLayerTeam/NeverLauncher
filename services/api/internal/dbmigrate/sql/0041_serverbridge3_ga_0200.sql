-- NeverLauncher 0.20.0: ServerBridge 3 GA протокол-состояние миграция поддержка.
-- Протокол v3 является зафиксированный GA сетевой контракт. Протокол v2 строки оставаться readable
-- только для compatibility/deprecation и являются поверхность для явный оператор миграция.
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_protocol_migration_0200
    ON server_bridge_nodes_v2(protocol_version,last_heartbeat_at DESC,id)
    WHERE status='active' AND protocol_version=2;

COMMENT ON COLUMN server_bridge_nodes_v2.protocol_version IS
    'Negotiated ServerBridge wire protocol. Since NeverLauncher 0.20.0, v3 is frozen GA; v2 is compatibility/deprecation-only and must migrate with nl server-bridge migrate-v3.';
COMMENT ON COLUMN server_bridge_join_tickets_v2.protocol_version IS
    'Wire protocol selected for the target ServerBridge node. v2 is compatibility/deprecation-only since NeverLauncher 0.20.0.';
COMMENT ON COLUMN server_bridge_handoffs_v2.protocol_version IS
    'Wire protocol selected for the target ServerBridge node. v2 is compatibility/deprecation-only since NeverLauncher 0.20.0.';

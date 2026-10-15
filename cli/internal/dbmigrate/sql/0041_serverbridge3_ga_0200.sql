-- NeverLauncher 0.20.0: миграция состояния Protocol v3 для ServerBridge 3 GA. Protocol v3
-- — зафиксированный сетевой контракт GA. Строки Protocol v2 доступны только для чтения
-- ради совместимости и вывода из эксплуатации; оператору предлагается явная миграция.
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_protocol_migration_0200
    ON server_bridge_nodes_v2(protocol_version,last_heartbeat_at DESC,id)
    WHERE status='active' AND protocol_version=2;

COMMENT ON COLUMN server_bridge_nodes_v2.protocol_version IS
    'Negotiated ServerBridge wire protocol. Since NeverLauncher 0.20.0, v3 is frozen GA; v2 is compatibility/deprecation-only and must migrate with nl server-bridge migrate-v3.';
COMMENT ON COLUMN server_bridge_join_tickets_v2.protocol_version IS
    'Wire protocol selected for the target ServerBridge node. v2 is compatibility/deprecation-only since NeverLauncher 0.20.0.';
COMMENT ON COLUMN server_bridge_handoffs_v2.protocol_version IS
    'Wire protocol selected for the target ServerBridge node. v2 is compatibility/deprecation-only since NeverLauncher 0.20.0.';

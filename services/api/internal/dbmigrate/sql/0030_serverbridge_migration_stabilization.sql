-- Launcher 0.14.10: миграция и стабилизация ServerBridge. Модель
-- протокола и данных 0.14.1–0.14.9 сохраняется; просроченные временные
-- строки закрываются и добавляются индексы для поиска передач 0.14.8+
-- и обслуживания. Идентичности узлов, действительные разрешения,
-- топология и целостность выпусков не переписываются.

-- Нормализуйте временные строки, которые могли остаться активными,
-- если реплики 0.14.9 остановились до очередного обслуживания.
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

-- Поиск доказательства источника при выдаче прокси разрешения на передачу в бэкенд.
-- Предотвращает сортировку растущей полной истории разрешений при долгой эксплуатации.
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_consumed_source_01410
    ON server_bridge_join_tickets_v2(server_id, username_normalized, consumed_at DESC)
    WHERE status='consumed';

-- При определении цели допустим канонический ID узла или имя бэкенда во время работы.
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_name_folded_01410
    ON server_bridge_nodes_v2(lower(name), id);

-- Ограниченная очистка по сроку хранения просматривает конечные строки по возрасту, а не по первичному ключу.
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

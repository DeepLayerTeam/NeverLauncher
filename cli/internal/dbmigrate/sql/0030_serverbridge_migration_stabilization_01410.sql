-- NeverLauncher 0.14.10: ServerBridge миграция + стабилизация.
-- Этот миграция сохраняет 0.14.1-0.14.9 protocol/data модель intact пока
-- запечатывать истёкший временный строки и добавляя индексы для фактический 0.14.8+
-- передача lookup/maintenance пути. Нет узел идентичности, билеты тот являются по-прежнему
-- действительный, топология привязка, или релиз-целостность состояние являются перезаписан.

-- Нормализовать временный строки тот может имеют оставаться активный когда 0.14.9 реплики
-- были остановлен до их opportunistic обслуживание успешно ran.
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

-- Исходник-доказательство поиск используется когда прокси mints серверная часть передача. Этот avoids 
-- growing sort над полный билет история на long-lived установка.
CREATE INDEX IF NOT EXISTS idx_server_bridge_join_consumed_source_01410
    ON server_bridge_join_tickets_v2(server_id, username_normalized, consumed_at DESC)
    WHERE status='consumed';

-- Цель разрешение принимает канонический узел ID или среда выполнения серверная часть имя.
CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_name_folded_01410
    ON server_bridge_nodes_v2(lower(name), id);

-- Ограниченный хранение очистка scans конечный строки через age, не через primary ключ.
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

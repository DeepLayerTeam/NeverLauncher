-- NeverLauncher 0.19.8: Универсальный Сервер Адаптеры.
-- Expands канонический ServerBridge тип к Quilt, Sponge и Vanilla вспомогательный процесс.
-- Гибридный ядра являются намеренно NOT admitted здесь; они требовать отдельный сертификация группа.
ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','quilt','forge','neoforge','sponge','vanilla'));
COMMENT ON CONSTRAINT server_bridge_nodes_v2_kind_check ON server_bridge_nodes_v2 IS
    'NeverLauncher 0.19.8 canonical Universal Server Adapter kinds; hybrid cores require separate certification';

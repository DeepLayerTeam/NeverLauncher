-- Launcher 0.14.7: мосты Forge и NeoForge Server Bridge. Расширяет фиксированный
-- набор типов узлов ServerBridge, сохраняя текущие идентичности и разрешения.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge'));

COMMENT ON CONSTRAINT server_bridge_nodes_v2_kind_check ON server_bridge_nodes_v2 IS
    'Launcher 0.14.7 canonical ServerBridge kinds; Forge and NeoForge are distinct integrity/identity namespaces';

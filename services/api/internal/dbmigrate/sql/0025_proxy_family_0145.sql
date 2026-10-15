-- NeverLauncher 0.14.5: семейство прокси Velocity/BungeeCord/Waterfall. Расширяет
-- постоянный инвариант типа узла ServerBridge для совместимых с Bungee прокси,
-- сохраняя Protocol v2, Ed25519-идентичность и одноразовые разрешения.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia'));

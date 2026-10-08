-- NeverLauncher 0.14.5 — Прокси семейство: Velocity/BungeeCord/Waterfall.
-- Expand долговременный ServerBridge узел-тип инвариант для Bungee-compatible
-- прокси пока сохраняя Протокол v2, Ed25519 идентичность и одноразовый билеты.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia'));

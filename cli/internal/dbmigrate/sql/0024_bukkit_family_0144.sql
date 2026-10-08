-- NeverLauncher 0.14.4 — Bukkit семейство: Bukkit/Spigot/Paper/Purpur/Folia.
-- Expand долговременный ServerBridge узел-тип инвариант к полный
-- Bukkit-compatible семейство пока сохраняя Протокол v2 и криптографический
-- идентичность семантика из 0.14.1-0.14.3.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bukkit','spigot','paper','purpur','folia'));

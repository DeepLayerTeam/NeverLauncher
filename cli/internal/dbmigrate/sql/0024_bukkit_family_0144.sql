-- Launcher 0.14.4: семейство Bukkit — Bukkit/Spigot/Paper/Purpur/Folia.
-- Расширяет постоянный инвариант типа узла ServerBridge на всё
-- совместимое семейство Bukkit, сохраняя семантику Protocol v2
-- и криптографической идентичности 0.14.1–0.14.3.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bukkit','spigot','paper','purpur','folia'));

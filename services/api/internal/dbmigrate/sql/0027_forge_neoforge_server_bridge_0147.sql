-- NeverLauncher 0.14.7: Forge + NeoForge Server Bridge.
-- Extends the sealed ServerBridge node-kind domain while preserving existing node identities/tickets.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge'));

COMMENT ON CONSTRAINT server_bridge_nodes_v2_kind_check ON server_bridge_nodes_v2 IS
    'NeverLauncher 0.14.7 canonical ServerBridge kinds; Forge and NeoForge are distinct integrity/identity namespaces';

-- NeverLauncher 0.14.6: Fabric Server Bridge becomes a first-class Protocol v2 node kind.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric'));

-- NeverLauncher 0.19.8: Universal Server Adapters.
-- Expands canonical ServerBridge kinds to Quilt, Sponge and the Vanilla sidecar.
-- Hybrid cores are intentionally NOT admitted here; they require a separate certification cohort.
ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','quilt','forge','neoforge','sponge','vanilla'));
COMMENT ON CONSTRAINT server_bridge_nodes_v2_kind_check ON server_bridge_nodes_v2 IS
    'NeverLauncher 0.19.8 canonical Universal Server Adapter kinds; hybrid cores require separate certification';

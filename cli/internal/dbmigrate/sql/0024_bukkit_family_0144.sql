-- NeverLauncher 0.14.4 — Bukkit family: Bukkit/Spigot/Paper/Purpur/Folia.
-- Expand the durable ServerBridge node-kind invariant to the complete
-- Bukkit-compatible family while preserving Protocol v2 and cryptographic
-- identity semantics from 0.14.1-0.14.3.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bukkit','spigot','paper','purpur','folia'));

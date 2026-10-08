-- NeverLauncher 0.14.5 — Proxy family: Velocity/BungeeCord/Waterfall.
-- Expand the durable ServerBridge node-kind invariant for Bungee-compatible
-- proxies while preserving Protocol v2, Ed25519 identity and one-time tickets.

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_kind_check;

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_kind_check
        CHECK (kind IN ('velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia'));

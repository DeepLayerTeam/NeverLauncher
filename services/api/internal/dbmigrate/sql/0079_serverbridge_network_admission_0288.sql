-- Operator admission ceiling, separate from the node-signed Minecraft capacity.
-- NULL = no override, 0 = deny all new admissions. It may only narrow admission.
ALTER TABLE server_bridge_nodes_v2
    ADD COLUMN IF NOT EXISTS operator_capacity_max INTEGER,
    ADD COLUMN IF NOT EXISTS operator_capacity_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS operator_capacity_updated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS operator_capacity_updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_operator_capacity_bounds_0288;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_operator_capacity_bounds_0288
    CHECK ((operator_capacity_max IS NULL OR operator_capacity_max BETWEEN 0 AND 1000000)
      AND operator_capacity_revision >= 0);
COMMENT ON COLUMN server_bridge_nodes_v2.operator_capacity_max IS
    'Admin-side admission limit. NULL means signed node capacity only, zero denies new routes and handoffs. Does not alter the node-signed snapshot.';

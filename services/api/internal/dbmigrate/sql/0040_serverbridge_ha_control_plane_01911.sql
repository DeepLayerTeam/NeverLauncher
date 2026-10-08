-- NeverLauncher 0.19.11: HA ServerBridge управление-плоскость последовательность и ограждённый владение.
ALTER TABLE server_bridge_control_commands_v3
    ADD COLUMN IF NOT EXISTS delivery_sequence BIGSERIAL,
    ADD COLUMN IF NOT EXISTS lease_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS lease_token TEXT NOT NULL DEFAULT '';

-- Существующий строки получать детерминированный последовательность значения из backing последовательность.
UPDATE server_bridge_control_commands_v3
SET delivery_sequence = nextval(pg_get_serial_sequence('server_bridge_control_commands_v3','delivery_sequence'))
WHERE delivery_sequence IS NULL;
ALTER TABLE server_bridge_control_commands_v3
    ALTER COLUMN delivery_sequence SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_server_bridge_control_delivery_sequence_01911
    ON server_bridge_control_commands_v3(delivery_sequence);
CREATE INDEX IF NOT EXISTS idx_server_bridge_control_resume_01911
    ON server_bridge_control_commands_v3(server_id,runtime_epoch,runtime_id,delivery_sequence)
    WHERE status IN ('pending','leased');
CREATE INDEX IF NOT EXISTS idx_server_bridge_control_owner_01911
    ON server_bridge_control_commands_v3(server_id,lease_owner,lease_until)
    WHERE status='leased';

ALTER TABLE server_bridge_control_commands_v3
    DROP CONSTRAINT IF EXISTS server_bridge_control_commands_v3_lease_owner_shape_01911;
ALTER TABLE server_bridge_control_commands_v3
    ADD CONSTRAINT server_bridge_control_commands_v3_lease_owner_shape_01911 CHECK (
        (status='leased' AND length(lease_owner) BETWEEN 16 AND 128 AND length(lease_token) BETWEEN 16 AND 160)
        OR status<>'leased'
        OR completed_at IS NOT NULL
    );

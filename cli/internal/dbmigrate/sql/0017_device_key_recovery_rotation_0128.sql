-- NeverLauncher 0.12.8 — cross-platform device-key recovery and rotation.
-- Preserve the old trusted-device row as a permanent tombstone and link it to
-- the replacement identity for audit/incident-response continuity.
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replaced_at TIMESTAMPTZ NULL;
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replaced_by_device_id TEXT NOT NULL DEFAULT '';
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replacement_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_trusted_devices_replacement
    ON trusted_devices(user_id, replaced_by_device_id)
    WHERE replaced_by_device_id <> '';

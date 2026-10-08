-- NeverLauncher 0.12.8 — кроссплатформенный ключ устройства восстановление и ротация.
-- Preserve старый доверенное устройство строка как постоянный метка удаления и связь это к
-- замена идентичность для audit/incident-response continuity.
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replaced_at TIMESTAMPTZ NULL;
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replaced_by_device_id TEXT NOT NULL DEFAULT '';
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replacement_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_trusted_devices_replacement
    ON trusted_devices(user_id, replaced_by_device_id)
    WHERE replaced_by_device_id <> '';

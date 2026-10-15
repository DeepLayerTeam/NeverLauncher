-- NeverLauncher 0.12.8: кроссплатформенное восстановление и ротация ключей
-- устройства. Сохраните прежнюю доверенную запись устройства как постоянное
-- надгробие и свяжите с новой идентичностью для аудита и расследований.
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replaced_at TIMESTAMPTZ NULL;
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replaced_by_device_id TEXT NOT NULL DEFAULT '';
ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS replacement_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_trusted_devices_replacement
    ON trusted_devices(user_id, replaced_by_device_id)
    WHERE replaced_by_device_id <> '';

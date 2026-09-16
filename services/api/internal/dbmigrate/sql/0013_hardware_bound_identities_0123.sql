-- NeverLauncher 0.12.3 — Hardware-bound identities.
-- This migration records the local key binding separately from remote trust assurance.
-- hardware binding is descriptive until a later attestation release verifies the provider remotely.

ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS key_binding TEXT NOT NULL DEFAULT 'software';
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS hardware_provider TEXT NOT NULL DEFAULT '';

UPDATE trusted_devices
SET key_binding='software', hardware_provider=''
WHERE key_binding IS NULL OR btrim(key_binding)='';

ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_key_algorithm_check;
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_key_binding_check;
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_hardware_provider_check;

ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_key_algorithm_check
    CHECK (key_algorithm IN ('ed25519','p256'));
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_key_binding_check
    CHECK (key_binding IN ('software','hardware'));
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_hardware_provider_check
    CHECK (
        (key_binding='software' AND key_algorithm='ed25519' AND hardware_provider='') OR
        (key_binding='hardware' AND key_algorithm='p256' AND length(btrim(hardware_provider)) BETWEEN 1 AND 96)
    );

CREATE INDEX IF NOT EXISTS idx_trusted_devices_binding
    ON trusted_devices(user_id,key_binding,status,updated_at DESC);

-- NeverLauncher 0.12.4 — Challenge-response device attestation.
-- The attestation proves fresh possession of the already-registered device key.
-- hardware_provider remains descriptive because hardware-enclave 0.2.10 does not expose
-- vendor TPM quote / Secure Enclave certificate attestation to the application.

ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS attestation_state TEXT NOT NULL DEFAULT 'unattested';
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS attestation_method TEXT NOT NULL DEFAULT '';
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS attested_at TIMESTAMPTZ;
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS attestation_expires_at TIMESTAMPTZ;

UPDATE trusted_devices
SET attestation_state='unattested', attestation_method='', attested_at=NULL, attestation_expires_at=NULL
WHERE attestation_state IS NULL OR btrim(attestation_state)='';

ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_assurance_check;
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_attestation_state_check;
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_attestation_window_check;

ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_assurance_check
    CHECK (assurance IN ('proof-of-possession','challenge-response-attested'));
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_attestation_state_check
    CHECK (attestation_state IN ('unattested','verified','revoked'));
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_attestation_window_check
    CHECK (
        (attestation_state='unattested' AND attestation_method='' AND attested_at IS NULL AND attestation_expires_at IS NULL AND assurance='proof-of-possession') OR
        (attestation_state='verified' AND attestation_method='challenge-response-v1' AND attested_at IS NOT NULL AND attestation_expires_at>attested_at AND assurance='challenge-response-attested') OR
        (attestation_state='revoked')
    );

ALTER TABLE device_challenges DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;
ALTER TABLE device_challenges ADD CONSTRAINT device_challenges_purpose_check
    CHECK (purpose IN ('register','session-bind','attest'));

CREATE INDEX IF NOT EXISTS idx_trusted_devices_attestation
    ON trusted_devices(user_id,attestation_state,attestation_expires_at DESC)
    WHERE status='active';

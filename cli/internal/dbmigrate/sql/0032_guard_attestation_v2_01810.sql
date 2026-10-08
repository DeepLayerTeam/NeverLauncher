-- NeverLauncher 0.18.10 — Guard Attestation v2 challenge/ticket purposes.
--
-- Attestation v2 is intentionally post-launch on Windows: a fresh challenge is
-- completed only after NeverGuard Sensor and Continuous Guard are active. The
-- resulting short-lived ticket is consumed exactly once by ServerBridge join.
-- Existing v1 bootstrap purposes remain valid for Minecraft-session issuance.

ALTER TABLE device_challenges
    DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;

ALTER TABLE device_challenges
    ADD CONSTRAINT device_challenges_purpose_check
    CHECK (purpose IN (
        'register',
        'session-bind',
        'attest',
        'key-rotate',
        'key-recover',
        'guard-attest-v1',
        'guard-launch-v1',
        'guard-attest-v2',
        'guard-continuous-join-v2'
    ));

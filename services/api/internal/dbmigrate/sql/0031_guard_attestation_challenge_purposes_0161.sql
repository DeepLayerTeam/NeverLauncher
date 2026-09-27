-- NeverLauncher 0.16.1 — Guard Attestation challenge-purpose schema completion.
--
-- Guard Attestation 0.13.4 introduced two one-shot challenge purposes backed by
-- device_challenges: guard-attest-v1 for the challenge/response proof and
-- guard-launch-v1 for the short-lived launch ticket consumed by Minecraft auth.
-- The HTTP/repository paths have shipped since 0.13.4, but the PostgreSQL CHECK
-- constraint was last rebuilt by 0.12.10 and therefore rejected both values.
--
-- This migration only widens the enumerated purpose set. It does not weaken
-- challenge expiry, ownership, single-use consumption, signature verification,
-- release allowlisting, or any other Guard/Device Trust security invariant.

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
        'guard-launch-v1'
    ));

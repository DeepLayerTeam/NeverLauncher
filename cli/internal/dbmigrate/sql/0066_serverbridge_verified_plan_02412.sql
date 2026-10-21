-- 0.24.12: One-use, PostgreSQL-atomic verified plan challenge purpose.
-- This expands the existing constraint; challenge rows retain all replay protection
-- and expiry semantics of the device trust service.
ALTER TABLE device_challenges DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;
ALTER TABLE device_challenges ADD CONSTRAINT device_challenges_purpose_check CHECK (purpose IN (
 'register','session-bind','attest','key-rotate','key-recover',
 'guard-attest-v1','guard-launch-v1','guard-attest-v2','guard-continuous-join-v2',
 'serverbridge-verified-plan-v1'
));

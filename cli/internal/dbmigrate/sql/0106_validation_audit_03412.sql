-- V12: append-only, privacy-preserving validation decision trail.
-- No user-controlled logs, credentials, account IDs or signed payloads live here.
CREATE TABLE validation_attempt_events_03412 (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 package_id text NOT NULL,
 run_id text NOT NULL DEFAULT '',
 kind text NOT NULL CHECK(kind IN ('staged-report','attestation','stable-gate')),
 outcome text NOT NULL CHECK(outcome IN ('recorded','accepted','rejected','blocked','eligible')),
 reason_code text NOT NULL CHECK(reason_code ~ '^[a-z0-9_.-]{1,96}$'),
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX validation_attempt_events_pkg_03412 ON validation_attempt_events_03412(package_id,id DESC);
CREATE FUNCTION validation_attempt_event_immutable_03412() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'validation audit is append-only' USING ERRCODE='23514';
END $$;
CREATE TRIGGER validation_attempt_event_immutable_03412 BEFORE UPDATE OR DELETE ON validation_attempt_events_03412
 FOR EACH ROW EXECUTE FUNCTION validation_attempt_event_immutable_03412();

-- Accepted evidence and received staged observations are recorded in the SAME
-- database transaction as the evidence, not in a fallible follow-up HTTP call.
CREATE FUNCTION validation_record_staged_03412() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO validation_attempt_events_03412(package_id,run_id,kind,outcome,reason_code,payload_sha256)
 VALUES(NEW.package_id,NEW.run_id,'staged-report','recorded','untrusted-observation',
        encode(sha256(convert_to(NEW.stages::text,'UTF8')),'hex'));
 RETURN NEW;
END $$;
CREATE TRIGGER validation_record_staged_03412 AFTER INSERT ON package_staged_runtime_runs_0342
 FOR EACH ROW EXECUTE FUNCTION validation_record_staged_03412();
CREATE FUNCTION validation_record_attestation_03412() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO validation_attempt_events_03412(package_id,run_id,kind,outcome,reason_code,payload_sha256)
 VALUES(NEW.package_id,NEW.run_id,'attestation','accepted','trusted-evidence-recorded',
        encode(sha256(convert_to(NEW.evidence::text || NEW.signature,'UTF8')),'hex'));
 RETURN NEW;
END $$;
CREATE TRIGGER validation_record_attestation_03412 AFTER INSERT ON package_validation_attestations_0345
 FOR EACH ROW EXECUTE FUNCTION validation_record_attestation_03412();

-- Preserve the observations referenced by signed ValidationEvidence, even if
-- a direct repository writer bypasses the HTTP handler.
CREATE TRIGGER validation_staged_immutable_03412 BEFORE UPDATE OR DELETE ON package_staged_runtime_runs_0342
 FOR EACH ROW EXECUTE FUNCTION stable_evidence_immutable_03411();

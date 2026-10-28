-- PostgreSQL 14+ built-in sha256(bytea); no external crypto extension.

-- V11: stable can advance only with a short-lived, one-use grant for a
-- complete set of existing, signed attestation rows. The grant is produced
-- by the backend evaluator; every write re-checks the persisted evidence.
CREATE TABLE stable_runtime_permits_03411 (
 token_sha256 text PRIMARY KEY CHECK(token_sha256 ~ '^[0-9a-f]{64}$'),
 package_id text NOT NULL REFERENCES release_versions(id),
 project_id text NOT NULL,
 manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[0-9a-f]{64}$'),
 artifact_sha256 text NOT NULL CHECK(artifact_sha256 ~ '^[0-9a-f]{64}$'),
 matrix_sha256 text NOT NULL CHECK(matrix_sha256 ~ '^[0-9a-f]{64}$'),
 targets jsonb NOT NULL CHECK(jsonb_typeof(targets)='array' AND jsonb_array_length(targets)>0 AND jsonb_array_length(targets)<=128),
 runs jsonb NOT NULL CHECK(jsonb_typeof(runs)='object'),
 issued_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL CHECK(expires_at<=issued_at+interval '5 minutes' AND expires_at>issued_at),
 consumed_at timestamptz
);
CREATE INDEX stable_runtime_permits_package_03411 ON stable_runtime_permits_03411(package_id, expires_at);

-- Intentionally not a manual certified flag. The trigger checks actual rows,
-- every mandated stage, run challenge, attestation freshness, and key revocation.
CREATE FUNCTION stable_runtime_permit_valid_03411(p_id text,p_manifest text,p_token text) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE g stable_runtime_permits_03411%ROWTYPE;
DECLARE t jsonb;
DECLARE e jsonb;
DECLARE run_id text;
DECLARE signing_key text;
DECLARE required_stages text[] := ARRAY['manifest-files','materialization','startup','loader-readiness','authentication','server-readiness','matching-server','gameplay-smoke','update-recovery'];
DECLARE stage text;
DECLARE item_count integer := 0;
DECLARE key_count integer;
BEGIN
 IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 SELECT * INTO g FROM stable_runtime_permits_03411
 WHERE token_sha256=encode(sha256(convert_to(p_token,'UTF8')),'hex') AND package_id=p_id
 AND manifest_sha256=p_manifest AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT count(*) INTO key_count FROM jsonb_object_keys(g.runs);
 IF key_count <> jsonb_array_length(g.targets) THEN RETURN false; END IF;
IF NOT EXISTS (SELECT 1 FROM (
 SELECT manifest_digest,artifact_digest,result FROM package_integrity_checks
 WHERE package_id=p_id ORDER BY checked_at DESC,id DESC LIMIT 1
 ) latest WHERE latest.manifest_digest=g.manifest_sha256 AND latest.artifact_digest=g.artifact_sha256
 AND latest.result='passed') THEN RETURN false; END IF;
 FOR t IN SELECT value FROM jsonb_array_elements(g.targets) LOOP
   item_count := item_count+1;
   run_id := g.runs->>(t->>'id');
   IF run_id IS NULL OR run_id='' THEN RETURN false; END IF;
   SELECT a.evidence INTO e FROM package_validation_attestations_0345 a
     JOIN package_validation_challenges_0346 c ON c.run_id=a.run_id
     WHERE a.run_id=run_id AND a.package_id=g.package_id AND a.manifest_sha256=g.manifest_sha256
       AND a.artifact_sha256=g.artifact_sha256 AND c.package_id=g.package_id
       AND c.manifest_sha256=g.manifest_sha256 AND c.artifact_sha256=g.artifact_sha256
       AND c.target_matrix_sha256=g.matrix_sha256
       AND a.evidence->>'runNonce'=c.nonce
       AND a.evidence->>'targetMatrixSha256'=g.matrix_sha256
       AND a.evidence->>'schemaVersion'='neverlauncher.validation-evidence.v4'
       AND a.evidence->>'audience'='neverlauncher-api/validation-evidence/0.34.7'
       AND a.evidence->>'purpose'='staged-package-runtime-verification'
       AND (a.evidence->>'expiresAt')::timestamptz > clock_timestamp()
     FOR SHARE OF a,c;
   IF NOT FOUND THEN RETURN false; END IF;
   signing_key:=e->>'signerKeyId';
   IF signing_key IS NULL OR signing_key !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
   PERFORM pg_advisory_xact_lock(hashtextextended('validation-signer:'||signing_key,0));
   IF EXISTS(SELECT 1 FROM package_validation_revoked_keys_0346 WHERE fingerprint=signing_key) THEN RETURN false; END IF;
   IF t->>'projectId' <> g.project_id OR t->>'manifestSha256' <> g.manifest_sha256 OR t->>'artifactSha256' <> g.artifact_sha256 THEN RETURN false; END IF;
   IF NOT (e @> jsonb_build_object(
     'targetId',t->>'id','packageVersion',t->>'version','manifestSha256',t->>'manifestSha256',
     'artifactSha256',t->>'artifactSha256','resolvedPlanSha256',t->>'resolvedPlanSha256',
     'sourceSha',t->>'sourceSha','buildSha',t->>'buildSha','javaSha256',t->>'javaSha256',
     'javaVersion',t->>'javaVersion','os',t->>'os','arch',t->>'arch','loader',t->>'loader',
     'installAdapterSha256',t->>'installAdapterSha256','guardMode',t->>'guardMode',
     'guardPolicySha256',t->>'guardPolicySha256','serverBridgeSha256',t->>'serverBridgeSha256',
     'serverPluginVersion',t->>'serverPluginVersion','preset',t->>'preset',
     'authenticationMode',t->>'authenticationMode')) THEN RETURN false; END IF;
   FOREACH stage IN ARRAY required_stages LOOP
      IF e->'stages'->>stage IS DISTINCT FROM 'passed' THEN RETURN false; END IF;
   END LOOP;
 END LOOP;
 RETURN item_count > 0;
END $$;

-- All stable writes (including direct SQL, promotion, cutover, rollback)
-- must have an independently validated, one-use grant in the SAME transaction.
CREATE OR REPLACE FUNCTION stable_runtime_release_guard_0341() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE must_check boolean:=false;
DECLARE token text;
BEGIN
 IF TG_OP='INSERT' THEN
   must_check := lower(btrim(NEW.channel))='stable' AND NEW.status='published';
 ELSE
   IF OLD.project_id IS DISTINCT FROM NEW.project_id OR OLD.profile_id IS DISTINCT FROM NEW.profile_id
      OR OLD.channel IS DISTINCT FROM NEW.channel OR OLD.version IS DISTINCT FROM NEW.version
      OR OLD.id IS DISTINCT FROM NEW.id THEN
      RAISE EXCEPTION 'stable_runtime_gate_03411: release identity immutable' USING ERRCODE='23514';
   END IF;
   must_check := lower(btrim(NEW.channel))='stable' AND NEW.status='published' AND OLD.status IS DISTINCT FROM NEW.status;
 END IF;
 IF must_check THEN
   token:=current_setting('never.stable_gate_token',true);
   IF NOT stable_runtime_permit_valid_03411(NEW.id,
      (SELECT manifest_sha256 FROM stable_runtime_permits_03411 WHERE token_sha256=encode(sha256(convert_to(token,'UTF8')),'hex')),
      token) THEN
     RAISE EXCEPTION 'stable_runtime_gate_03411: certified release permit missing/invalid' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION stable_runtime_head_guard_0341() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE token text;
DECLARE check_stable boolean:=false;
BEGIN
 IF TG_OP='DELETE' THEN
   IF lower(btrim(OLD.channel))='stable' THEN
      RAISE EXCEPTION 'stable_runtime_gate_03411: stable channel deletion prohibited' USING ERRCODE='23514';
   END IF;
   RETURN OLD;
 END IF;
 check_stable := lower(btrim(NEW.channel))='stable';
 IF TG_OP='UPDATE' THEN
   IF lower(btrim(OLD.channel))='stable' THEN check_stable:=true; END IF;
 END IF;
 IF NOT check_stable THEN RETURN NEW; END IF;
 IF lower(btrim(NEW.channel))<>'stable' OR NEW.revision<1 THEN
   RAISE EXCEPTION 'stable_runtime_gate_03411: invalid stable head transition' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' THEN
   IF NEW.revision<>OLD.revision+1 OR NEW.project_id<>OLD.project_id OR NEW.profile_id<>OLD.profile_id THEN
     RAISE EXCEPTION 'stable_runtime_gate_03411: invalid stable head revision/scope' USING ERRCODE='23514';
   END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM release_versions WHERE id=NEW.release_id AND project_id=NEW.project_id
     AND profile_id=NEW.profile_id AND channel='stable' AND version=NEW.version AND status='published') THEN
   RAISE EXCEPTION 'stable_runtime_gate_03411: stable head target must be published' USING ERRCODE='23514';
 END IF;
 token:=current_setting('never.stable_gate_token',true);
 IF NOT stable_runtime_permit_valid_03411(NEW.release_id,NEW.manifest_digest,token) THEN
   RAISE EXCEPTION 'stable_runtime_gate_03411: target evidence missing/failed/inconclusive/expired or policy changed' USING ERRCODE='23514';
 END IF;
 UPDATE stable_runtime_permits_03411 SET consumed_at=clock_timestamp()
 WHERE token_sha256=encode(sha256(convert_to(token,'UTF8')),'hex') AND consumed_at IS NULL;
 RETURN NEW;
END $$;
-- PostgreSQL 14+ is already required by existing migrations.

-- Accepted evidence/challenges must not be changed after the verifier saved
-- them. Emergency signer revocation is a separate append-only record.
CREATE FUNCTION stable_evidence_immutable_03411() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'stable_runtime_gate_03411: accepted validation evidence immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER stable_attestation_immutable_03411 BEFORE UPDATE OR DELETE ON package_validation_attestations_0345 FOR EACH ROW EXECUTE FUNCTION stable_evidence_immutable_03411();
CREATE TRIGGER stable_challenge_immutable_03411 BEFORE UPDATE OR DELETE ON package_validation_challenges_0346 FOR EACH ROW EXECUTE FUNCTION stable_evidence_immutable_03411();
CREATE TRIGGER stable_revocation_immutable_03411 BEFORE UPDATE OR DELETE ON package_validation_revoked_keys_0346 FOR EACH ROW EXECUTE FUNCTION stable_evidence_immutable_03411();

-- A permit is single-use even under direct SQL: nothing may reset consumed_at,
-- alter its snapshot, or replace its required target list after creation.
CREATE FUNCTION stable_runtime_permit_immutable_03411() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR
    (to_jsonb(NEW)-'consumed_at') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_at') THEN
    RAISE EXCEPTION 'stable_runtime_gate_03411: one-use permit immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER stable_runtime_permit_immutable_03411 BEFORE UPDATE ON stable_runtime_permits_03411
 FOR EACH ROW EXECUTE FUNCTION stable_runtime_permit_immutable_03411();

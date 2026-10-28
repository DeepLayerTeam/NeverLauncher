-- 0.35.0 GA: a successful stable integrity check freezes the artifact
-- metadata. Without this, the SQL head guard could observe an old PASS after
-- a direct SQL mutation of files or manifest between verification and commit.
CREATE FUNCTION stable_snapshot_frozen_0350(p_id text) RETURNS boolean
LANGUAGE sql STABLE AS $$
 SELECT EXISTS (
   SELECT 1 FROM release_versions v WHERE v.id=p_id AND lower(btrim(v.channel))='stable'
     AND (v.status='published' OR EXISTS (
       SELECT 1 FROM package_integrity_checks i WHERE i.package_id=p_id AND i.result='passed'
     ))
 );
$$;

CREATE FUNCTION stable_files_guard_0350() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'INSERT' AND stable_snapshot_frozen_0350(OLD.version_id) THEN
   RAISE EXCEPTION 'stable_runtime_gate_0350: verified stable file snapshot immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP <> 'DELETE' AND stable_snapshot_frozen_0350(NEW.version_id) THEN
   RAISE EXCEPTION 'stable_runtime_gate_0350: verified stable file snapshot immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER stable_files_guard_0350 BEFORE INSERT OR UPDATE OR DELETE ON files
 FOR EACH ROW EXECUTE FUNCTION stable_files_guard_0350();

CREATE FUNCTION stable_integrity_immutable_0350() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF stable_snapshot_frozen_0350(OLD.package_id) OR
   (TG_OP='UPDATE' AND stable_snapshot_frozen_0350(NEW.package_id)) THEN
   RAISE EXCEPTION 'stable_runtime_gate_0350: stable integrity history immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER stable_integrity_immutable_0350 BEFORE UPDATE OR DELETE ON package_integrity_checks
 FOR EACH ROW EXECUTE FUNCTION stable_integrity_immutable_0350();

-- Retain the V11 permit/evidence checks, and additionally prevent changing a
-- certified stable release after it was published. Publishing still verifies
-- the permit inside the same transaction, at the existing V11 guard.
CREATE OR REPLACE FUNCTION stable_runtime_release_guard_0341() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE token text;
DECLARE must_check boolean:=false;
BEGIN
 IF TG_OP='INSERT' THEN
   must_check := lower(btrim(NEW.channel))='stable' AND NEW.status='published';
 ELSE
   IF OLD.project_id IS DISTINCT FROM NEW.project_id OR OLD.profile_id IS DISTINCT FROM NEW.profile_id
      OR OLD.channel IS DISTINCT FROM NEW.channel OR OLD.version IS DISTINCT FROM NEW.version
      OR OLD.id IS DISTINCT FROM NEW.id THEN
     RAISE EXCEPTION 'stable_runtime_gate_0350: release identity immutable' USING ERRCODE='23514';
   END IF;
   IF lower(btrim(OLD.channel))='stable' THEN
     IF OLD.status='published' AND (
          NEW.status IS DISTINCT FROM OLD.status OR NEW.manifest IS DISTINCT FROM OLD.manifest
          OR NEW.published_at IS DISTINCT FROM OLD.published_at) THEN
       RAISE EXCEPTION 'stable_runtime_gate_0350: published stable release immutable' USING ERRCODE='23514';
     END IF;
     IF NEW.manifest IS DISTINCT FROM OLD.manifest AND stable_snapshot_frozen_0350(OLD.id) THEN
       RAISE EXCEPTION 'stable_runtime_gate_0350: integrity-verified stable manifest immutable' USING ERRCODE='23514';
     END IF;
   END IF;
   must_check := lower(btrim(NEW.channel))='stable' AND NEW.status='published' AND OLD.status IS DISTINCT FROM NEW.status;
 END IF;
 IF must_check THEN
   token := current_setting('never.stable_gate_token',true);
   IF token IS NULL OR token !~ '^[0-9a-f]{64}$' OR
      NOT stable_runtime_permit_valid_03411(NEW.id,
       (SELECT manifest_sha256 FROM stable_runtime_permits_03411
         WHERE token_sha256=encode(sha256(convert_to(token,'UTF8')),'hex')),
       token) THEN
     RAISE EXCEPTION 'stable_runtime_gate_0350: fresh trusted runtime permit missing or invalid' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION stable_release_delete_guard_0350() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF lower(btrim(OLD.channel))='stable' AND stable_snapshot_frozen_0350(OLD.id) THEN
   RAISE EXCEPTION 'stable_runtime_gate_0350: verified stable release cannot be deleted' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER stable_release_delete_guard_0350 BEFORE DELETE ON release_versions
 FOR EACH ROW EXECUTE FUNCTION stable_release_delete_guard_0350();

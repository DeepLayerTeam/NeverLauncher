-- 0.34.1 V11: stable cannot advance until real attested staged execution is available.
-- Existing stable heads remain readable. A new stable head, an advance,
-- cutover, rollback, direct SQL write or manual status change is rejected.
-- A future verifier migration must replace this guard atomically; there is no
-- session variable, administrator or project policy escape hatch.
CREATE FUNCTION stable_runtime_release_guard_0341() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
   IF lower(btrim(NEW.channel))='stable' AND NEW.status='published' THEN
     RAISE EXCEPTION 'stable_runtime_gate_0341: trusted runtime validation unavailable; stable release status denied' USING ERRCODE='23514';
   END IF;
 ELSE
   IF OLD.project_id IS DISTINCT FROM NEW.project_id OR
      OLD.profile_id IS DISTINCT FROM NEW.profile_id OR
      OLD.channel IS DISTINCT FROM NEW.channel OR
      OLD.version IS DISTINCT FROM NEW.version OR OLD.id IS DISTINCT FROM NEW.id THEN
     RAISE EXCEPTION 'stable_runtime_gate_0341: release identity is immutable' USING ERRCODE='23514';
   END IF;
   IF lower(btrim(NEW.channel))='stable' AND NEW.status='published' AND
      OLD.status IS DISTINCT FROM NEW.status THEN
     RAISE EXCEPTION 'stable_runtime_gate_0341: trusted runtime validation unavailable; stable release status denied' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER stable_runtime_release_guard_0341
BEFORE INSERT OR UPDATE ON release_versions FOR EACH ROW
EXECUTE FUNCTION stable_runtime_release_guard_0341();

CREATE FUNCTION stable_runtime_head_guard_0341() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE channel_name TEXT;
BEGIN
 IF TG_OP='DELETE' THEN channel_name:=OLD.channel;
 ELSE channel_name:=NEW.channel; END IF;
 -- Include OLD on UPDATE to prevent renaming stable to an unprotected name.
 IF lower(btrim(channel_name))='stable' OR
    (TG_OP='UPDATE' AND lower(btrim(OLD.channel))='stable') THEN
   RAISE EXCEPTION 'stable_runtime_gate_0341: stable channel head is read-only until trusted runtime certification GA'
     USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER stable_runtime_head_guard_0341
BEFORE INSERT OR UPDATE OR DELETE ON channel_heads FOR EACH ROW
EXECUTE FUNCTION stable_runtime_head_guard_0341();

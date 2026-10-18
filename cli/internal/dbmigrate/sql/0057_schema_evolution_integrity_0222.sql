-- 0.22.2: v2 profile heads and release snapshots are immutable at the database boundary.
-- Additive migration; does not UPDATE release_versions.manifest or re-sign v1 releases.
-- Requires 0056; both API and CLI migration catalogs must contain this exact file.

-- Fail migration on pre-existing corruption. The migration never tries to
-- repair historic signed releases or to invent a missing profile revision.
DO $$
DECLARE broken BIGINT;
BEGIN
  SELECT count(*) INTO broken FROM profiles p
   LEFT JOIN profile_revisions_0221 h ON h.project_id=p.project_id AND h.profile_id=p.id
     AND h.revision=p.revision
   WHERE h.revision IS NULL OR h.schema_version IS DISTINCT FROM p.schema_version
     OR h.digest IS DISTINCT FROM p.digest OR
     h.spec IS DISTINCT FROM jsonb_build_object('projectId',p.project_id,'id',p.id,
       'name',p.name,'description',p.description,'loader',p.loader,
       'preset',p.preset,'isDefault',p.is_default);
  IF broken>0 THEN
    RAISE EXCEPTION '% untracked or mismatched profile heads; refusing 0057', broken;
  END IF;
  SELECT count(*) INTO broken FROM release_versions v
   WHERE v.manifest->>'schemaVersion'='2.0' AND NOT EXISTS (
     SELECT 1 FROM profile_revisions_0221 h
      WHERE h.project_id=v.project_id AND h.profile_id=v.profile_id
        AND h.revision=(v.manifest->'profileSnapshot'->>'revision')::bigint
        AND h.digest=v.manifest->'profileSnapshot'->>'digest'
        AND h.spec=v.manifest->'profileSnapshot'->'spec');
  IF broken>0 THEN
    RAISE EXCEPTION '% v2 releases reference invalid snapshots; refusing 0057', broken;
  END IF;
END;
$$;

CREATE FUNCTION enforce_profile_head_revision_0222() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.schema_version <> '2.0' OR NEW.revision < 1 OR
     NOT EXISTS (
       SELECT 1 FROM profile_revisions_0221 r
       WHERE r.project_id=NEW.project_id AND r.profile_id=NEW.id
         AND r.revision=NEW.revision AND r.digest=NEW.digest AND r.schema_version=NEW.schema_version
         AND r.spec=jsonb_build_object('projectId',NEW.project_id,'id',NEW.id,
           'name',NEW.name,'description',NEW.description,'loader',NEW.loader,
           'preset',NEW.preset,'isDefault',NEW.is_default)
     ) THEN
    RAISE EXCEPTION 'profile head is not backed by an immutable revision'
      USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;
-- Deferred until commit: SaveProfile updates the head and then appends its
-- revision in the same transaction, so both statements can be safely checked.
CREATE CONSTRAINT TRIGGER profile_head_revision_0222
 AFTER INSERT OR UPDATE ON profiles DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION enforce_profile_head_revision_0222();

CREATE FUNCTION enforce_release_snapshot_0222() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE snap JSONB;
DECLARE spec JSONB;
DECLARE historic BOOLEAN;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF OLD.status='published' AND (
        NEW.status IS DISTINCT FROM OLD.status OR
        NEW.manifest IS DISTINCT FROM OLD.manifest) THEN
      RAISE EXCEPTION 'published release cannot be rewritten' USING ERRCODE='23514';
    END IF;
    IF OLD.manifest->>'schemaVersion'='2.0' AND (
        NEW.manifest->>'schemaVersion' IS DISTINCT FROM '2.0' OR
        NEW.manifest->'profileSnapshot' IS DISTINCT FROM OLD.manifest->'profileSnapshot') THEN
      RAISE EXCEPTION 'release profileSnapshot is pinned' USING ERRCODE='23514';
    END IF;
    IF OLD.manifest->>'schemaVersion'='1.0' AND
       NEW.manifest->>'schemaVersion' IS DISTINCT FROM '1.0' THEN
      RAISE EXCEPTION 'legacy release schema cannot be silently upgraded' USING ERRCODE='23514';
    END IF;
  END IF;
  IF NEW.manifest->>'schemaVersion'='2.0' THEN
    snap := NEW.manifest->'profileSnapshot';
    spec := snap->'spec';
    IF snap IS NULL OR spec IS NULL OR
       snap->>'schemaVersion'<>'2.0' OR
       spec->>'projectId' IS DISTINCT FROM NEW.project_id OR
       spec->>'id' IS DISTINCT FROM NEW.profile_id OR
       NEW.manifest->>'projectId' IS DISTINCT FROM NEW.project_id OR
       NEW.manifest->>'profileId' IS DISTINCT FROM NEW.profile_id OR
       NEW.manifest->>'channel' IS DISTINCT FROM NEW.channel OR
       NEW.manifest->>'version' IS DISTINCT FROM NEW.version OR
       jsonb_typeof(snap->'revision') IS DISTINCT FROM 'number' OR
       (snap->>'revision') !~ '^[1-9][0-9]*$' THEN
      RAISE EXCEPTION 'invalid v2 release snapshot identity' USING ERRCODE='23514';
    END IF;
    SELECT EXISTS(SELECT 1 FROM profile_revisions_0221 h
      WHERE h.project_id=NEW.project_id AND h.profile_id=NEW.profile_id
        AND h.revision=(snap->>'revision')::bigint AND h.schema_version=snap->>'schemaVersion'
        AND h.digest=snap->>'digest' AND h.spec=spec) INTO historic;
    IF NOT historic THEN
      RAISE EXCEPTION 'release snapshot not found in immutable history' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER release_snapshot_0222 BEFORE INSERT OR UPDATE ON release_versions
 FOR EACH ROW EXECUTE FUNCTION enforce_release_snapshot_0222();

-- Published release contents are immutable even when application validation is bypassed.
CREATE FUNCTION prevent_published_release_delete_0222() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status='published' THEN
    RAISE EXCEPTION 'cannot delete published release' USING ERRCODE='23514';
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER prevent_published_release_delete_0222 BEFORE DELETE ON release_versions
 FOR EACH ROW EXECUTE FUNCTION prevent_published_release_delete_0222();

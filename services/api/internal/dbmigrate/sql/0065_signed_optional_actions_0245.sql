-- 0.24.5: signed executable optional actions schema 5.0.
-- Constraints are checked in Go publisher and native runtime before installation.
-- Retain immutable published manifests, release identity and profile snapshots.
-- Go and NeverRuntime validate the full v2 topology and digest.
CREATE OR REPLACE FUNCTION enforce_release_snapshot_0222() RETURNS trigger LANGUAGE plpgsql AS $$
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
    IF OLD.manifest->>'schemaVersion' IN ('2.0','3.0') AND (
        NEW.manifest->>'schemaVersion' IS DISTINCT FROM OLD.manifest->>'schemaVersion' OR
        NEW.manifest->'profileSnapshot' IS DISTINCT FROM OLD.manifest->'profileSnapshot') THEN
      RAISE EXCEPTION 'release profileSnapshot is pinned' USING ERRCODE='23514';
    END IF;
    IF OLD.manifest->>'schemaVersion'='1.0' AND
       NEW.manifest->>'schemaVersion' IS DISTINCT FROM '1.0' THEN
      RAISE EXCEPTION 'legacy release schema cannot be silently upgraded' USING ERRCODE='23514';
    END IF;
  END IF;
  IF NEW.manifest->>'schemaVersion' IN ('2.0','3.0') THEN
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
  IF NEW.manifest->>'schemaVersion'='3.0' AND
     (NEW.manifest->'componentCatalog' IS NULL OR
      COALESCE(NEW.manifest->'componentCatalog'->>'schemaVersion' NOT IN ('1.0','2.0','3.0','4.0','5.0'), TRUE) OR
      jsonb_typeof(NEW.manifest->'componentCatalog'->'components') IS DISTINCT FROM 'array' OR
      jsonb_typeof(NEW.manifest->'componentCatalog'->'revision') IS DISTINCT FROM 'number' OR
      (NEW.manifest->'componentCatalog'->>'revision') !~ '^[1-9][0-9]*$' OR
      COALESCE((NEW.manifest->'componentCatalog'->>'digest') !~ '^[0-9a-f]{64}$', TRUE)) THEN
    RAISE EXCEPTION 'invalid v3 component catalog snapshot' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;

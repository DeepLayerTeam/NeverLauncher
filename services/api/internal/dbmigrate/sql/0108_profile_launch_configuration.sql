-- Adds immutable revisioned launch defaults without rewriting old releases/digests.
ALTER TABLE profiles ADD COLUMN minecraft_version TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN loader_version TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN java_major INTEGER NOT NULL DEFAULT 0;
ALTER TABLE profiles ADD CONSTRAINT profiles_java_major_0382 CHECK (java_major=0 OR java_major BETWEEN 8 AND 255);

-- Preserve the deferred, fail-closed immutable-revision guard. Its old
-- jsonb_build_object comparison would reject every configured profile head.
CREATE OR REPLACE FUNCTION enforce_profile_head_revision_0222() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expected_spec JSONB;
BEGIN
  expected_spec := jsonb_build_object(
    'projectId', NEW.project_id, 'id', NEW.id, 'name', NEW.name,
    'description', NEW.description, 'loader', NEW.loader,
    'preset', NEW.preset, 'isDefault', NEW.is_default
  );
  IF NEW.minecraft_version <> '' THEN
    expected_spec := expected_spec || jsonb_build_object('minecraftVersion',NEW.minecraft_version);
  END IF;
  IF NEW.loader_version <> '' THEN
    expected_spec := expected_spec || jsonb_build_object('loaderVersion',NEW.loader_version);
  END IF;
  IF NEW.java_major <> 0 THEN
    expected_spec := expected_spec || jsonb_build_object('javaMajor',NEW.java_major);
  END IF;
  IF NEW.schema_version <> '2.0' OR NEW.revision < 1 OR NOT EXISTS (
    SELECT 1 FROM profile_revisions_0221 r
    WHERE r.project_id=NEW.project_id AND r.profile_id=NEW.id
      AND r.revision=NEW.revision AND r.digest=NEW.digest
      AND r.schema_version=NEW.schema_version AND r.spec=expected_spec
  ) THEN
    RAISE EXCEPTION 'profile head is not backed by an immutable revision'
      USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;

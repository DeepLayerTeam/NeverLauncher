-- Profile/Manifest v2. Existing signed release_versions.manifest JSONB is NEVER updated.
-- PostgreSQL >= 13 provides sha256(bytea) without requiring pgcrypto.
ALTER TABLE profiles ADD COLUMN schema_version TEXT NOT NULL DEFAULT '2.0';
ALTER TABLE profiles ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>0);
ALTER TABLE profiles ADD COLUMN digest TEXT NOT NULL DEFAULT '';

-- Go ProfileDigest joins the same fields with NUL (0x00); created/updated timestamps are excluded.
UPDATE profiles SET schema_version='2.0', revision=1,
 digest=encode(sha256(
 convert_to(project_id,'UTF8') || decode('00','hex') ||
 convert_to(id,'UTF8') || decode('00','hex') ||
 convert_to(name,'UTF8') || decode('00','hex') ||
 convert_to(description,'UTF8') || decode('00','hex') ||
 convert_to(loader,'UTF8') || decode('00','hex') ||
 convert_to(preset,'UTF8') || decode('00','hex') ||
 convert_to(is_default::text,'UTF8') ), 'hex');

CREATE TABLE profile_revisions_0221 (
 project_id TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0),
 schema_version TEXT NOT NULL CHECK(schema_version='2.0'),
 digest TEXT NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 spec JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(project_id,profile_id,revision),
 FOREIGN KEY(project_id,profile_id) REFERENCES profiles(project_id,id) ON DELETE RESTRICT
);
INSERT INTO profile_revisions_0221(project_id,profile_id,revision,schema_version,digest,spec,created_at)
SELECT project_id,id,revision,schema_version,digest,
 jsonb_build_object('projectId',project_id,'id',id,'name',name,'description',description,
  'loader',loader,'preset',preset,'isDefault',is_default),updated_at
FROM profiles;

-- History is append-only, even for privileged application roles. An explicit admin migration
-- would be required to redact/correct a historical revision.
CREATE FUNCTION prevent_profile_history_mutation_0221() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'profile revisions are immutable';
 END $$;
CREATE TRIGGER prevent_profile_revision_update_0221 BEFORE UPDATE OR DELETE ON profile_revisions_0221
 FOR EACH ROW EXECUTE FUNCTION prevent_profile_history_mutation_0221();
CREATE INDEX profile_revisions_0221_digest ON profile_revisions_0221(project_id,profile_id,digest);

-- New manifests contain their immutable snapshot inside the signed JSON payload; v1 published
-- rows are intentionally untouched. No mass rewrite/resign of release_versions is permitted.

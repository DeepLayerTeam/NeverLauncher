-- 0.25.10: migration provenance is committed atomically with texture selection.
-- No external user UUID is treated as an authenticated NeverLauncher identity.
CREATE TABLE texture_gravit_import_receipts (
  source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 100),
  external_row_id TEXT NOT NULL CHECK (length(external_row_id) BETWEEN 1 AND 150),
  external_user_uuid TEXT NOT NULL,
  original_hash TEXT NOT NULL,
  target_profile_uuid TEXT NOT NULL REFERENCES minecraft_profiles(uuid),
  kind TEXT NOT NULL CHECK (kind IN ('skin','cape')),
  normalized_digest TEXT NOT NULL REFERENCES texture_blobs(digest),
  assignment_id BIGINT NOT NULL REFERENCES texture_assignments(id),
  revision BIGINT NOT NULL,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(source_id,external_row_id)
);
CREATE INDEX idx_texture_gravit_import_target_02510 ON texture_gravit_import_receipts(target_profile_uuid,imported_at DESC);
ALTER TABLE texture_assignment_revisions DROP CONSTRAINT IF EXISTS texture_assignment_revisions_event_check;
ALTER TABLE texture_assignment_revisions ADD CONSTRAINT texture_assignment_revisions_event_check
 CHECK (event IN ('legacy-import','select','model-change','visibility-change','reset','upload','import','delete','gravit-import'));

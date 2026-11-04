-- 0.25.5: keep normalized textures in a per-owner library so players can
-- select previously uploaded assets without transferring PNGs again.
-- A cleared assignment is a revisioned tombstone, not a hard delete: it
-- preserves CAS tokens and history while immediately revoking public access.
CREATE TABLE texture_saved_items (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    digest TEXT NOT NULL REFERENCES texture_blobs(digest) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK(kind IN ('skin','cape')),
    model TEXT NOT NULL CHECK(model IN ('classic','slim')),
    source TEXT NOT NULL CHECK(source IN ('managed-upload','managed-url-import','imported')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_selected_at TIMESTAMPTZ,
    PRIMARY KEY(user_id,digest,kind),
    FOREIGN KEY(user_id,digest) REFERENCES texture_blob_owners(user_id,digest) ON DELETE CASCADE,
    CHECK(kind='skin' OR model='classic')
);
CREATE INDEX idx_texture_saved_items_user_kind ON texture_saved_items(user_id,kind,created_at DESC);
-- Backfill known managed PNG selections. Remote-reference URL records are not
-- valid library items, and private legacy images are not fetched on migration.
INSERT INTO texture_saved_items(user_id,digest,kind,model,source,last_selected_at)
SELECT a.user_id,a.blob_digest,a.kind,a.model,a.source,max(a.updated_at)
FROM texture_assignments a JOIN texture_blob_owners o
 ON o.user_id=a.user_id AND o.digest=a.blob_digest
WHERE a.blob_digest IS NOT NULL AND a.realm='local-project'
  AND a.source IN ('managed-upload','managed-url-import','imported')
GROUP BY a.user_id,a.blob_digest,a.kind,a.model,a.source
ON CONFLICT(user_id,digest,kind) DO NOTHING;

-- The original inline CHECK constraint is auto-named by PostgreSQL. Locate
-- and replace only that expression, leaving the independent source/kind checks.
DO $$
DECLARE rec RECORD;
DECLARE removed INTEGER := 0;
BEGIN
 FOR rec IN SELECT conname, pg_get_constraintdef(oid) AS definition
            FROM pg_constraint
            WHERE conrelid='texture_assignments'::regclass AND contype='c'
 LOOP
  IF rec.definition LIKE '%blob_digest%' AND rec.definition LIKE '%external_url%'
     AND rec.definition NOT LIKE '%source%' THEN
   EXECUTE format('ALTER TABLE texture_assignments DROP CONSTRAINT %I', rec.conname);
   removed := removed + 1;
  END IF;
 END LOOP;
 IF removed <> 1 THEN RAISE EXCEPTION 'expected exactly one legacy texture content check, found %',removed; END IF;
END $$;
ALTER TABLE texture_assignments ADD CONSTRAINT texture_assignments_content_0255
 CHECK (
    (active=false AND blob_digest IS NULL AND external_url='')
 OR (blob_digest IS NOT NULL AND external_url='')
 OR (blob_digest IS NULL AND external_url<>'')
 );
ALTER TABLE texture_assignment_revisions DROP CONSTRAINT IF EXISTS texture_assignment_revisions_event_check;
ALTER TABLE texture_assignment_revisions ADD CONSTRAINT texture_assignment_revisions_event_check
 CHECK (event IN ('legacy-import','select','model-change','visibility-change','reset','upload','import','delete'));

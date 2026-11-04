-- 0.25.4: preserve trusted provenance of imported, normalized remote PNGs.
-- The URL itself is never used as an assignment source, only the immutable
-- sha256 blob already validated and stored by the upload pipeline.
ALTER TABLE texture_assignments DROP CONSTRAINT IF EXISTS texture_assignments_source_check;
ALTER TABLE texture_assignments ADD CONSTRAINT texture_assignments_source_check
    CHECK (source IN ('managed-upload','managed-url-import','imported','remote-reference','official'));
ALTER TABLE texture_assignment_revisions DROP CONSTRAINT IF EXISTS texture_assignment_revisions_event_check;
ALTER TABLE texture_assignment_revisions ADD CONSTRAINT texture_assignment_revisions_event_check
    CHECK (event IN ('legacy-import','select','model-change','visibility-change','reset','upload','import'));

-- 0.25.2: record completed, verified PNG uploads as immutable revisions.
-- This migration does not modify legacy URL sources or official identities.
ALTER TABLE texture_assignment_revisions DROP CONSTRAINT IF EXISTS texture_assignment_revisions_event_check;
ALTER TABLE texture_assignment_revisions ADD CONSTRAINT texture_assignment_revisions_event_check
    CHECK(event IN ('legacy-import','select','model-change','visibility-change','reset','upload'));

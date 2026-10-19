-- Channel head is keyed by project, profile, and channel; not just the project-wide channel name.
-- Existing immutable releases are not changed or re-signed.
CREATE TABLE IF NOT EXISTS channel_heads (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 profile_id TEXT NOT NULL,
 channel TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK (revision > 0),
 release_id TEXT NOT NULL REFERENCES release_versions(id) ON DELETE CASCADE,
 version TEXT NOT NULL,
 manifest_digest TEXT NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(project_id,profile_id,channel)
);
CREATE INDEX IF NOT EXISTS channel_heads_release_idx_0228 ON channel_heads(release_id);
-- Backfill the newest published release without modifying any signed artifact.
WITH ranked AS (
 SELECT rv.*, ROW_NUMBER() OVER (PARTITION BY rv.project_id,rv.profile_id,rv.channel ORDER BY rv.published_at DESC NULLS LAST,rv.id DESC) AS rn
 FROM release_versions rv WHERE rv.status='published'
)
INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest,updated_at)
SELECT project_id,profile_id,channel,1,id,version,'',COALESCE(published_at,now())
FROM ranked WHERE rn=1
ON CONFLICT(project_id,profile_id,channel) DO NOTHING;

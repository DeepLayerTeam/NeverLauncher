-- 0.25.3: per-user deduplicated accounting, recoverable immutable object GC.
-- Blobs are globally deduplicated; owner quotas count unique (user,digest) pairs.
CREATE TABLE texture_blob_owners (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    digest TEXT NOT NULL REFERENCES texture_blobs(digest) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id,digest)
);
CREATE INDEX idx_texture_blob_owners_digest ON texture_blob_owners(digest);
ALTER TABLE texture_blobs ADD COLUMN gc_claimed_at TIMESTAMPTZ;
-- Refresh on every staging attempt, including reuse of an old verified digest,
-- so that GC cannot race an upload before the assignment CAS is committed.
ALTER TABLE texture_blobs ADD COLUMN last_upload_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX idx_texture_blob_gc_0253 ON texture_blobs(status,created_at,gc_claimed_at);
-- Existing verified blobs need an owner even if they predate 0.25.3.
INSERT INTO texture_blob_owners(user_id,digest)
SELECT DISTINCT user_id,blob_digest FROM texture_assignments WHERE blob_digest IS NOT NULL
ON CONFLICT DO NOTHING;

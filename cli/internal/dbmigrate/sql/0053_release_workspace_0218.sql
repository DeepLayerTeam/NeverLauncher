-- Release Workspace v0.21.8: durable, per-owner resumable drafts with CAS revisions.
CREATE TABLE release_drafts_0218 (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 owner_id TEXT NOT NULL,
 profile_id TEXT NOT NULL DEFAULT '',
 channel TEXT NOT NULL DEFAULT 'stable',
 version TEXT NOT NULL DEFAULT '',
 minecraft_version TEXT NOT NULL DEFAULT '',
 loader TEXT NOT NULL DEFAULT 'vanilla',
 package_id TEXT NOT NULL DEFAULT '',
 job_id TEXT NOT NULL DEFAULT '',
 step TEXT NOT NULL DEFAULT 'project',
 revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_release_drafts_0218_owner_project ON release_drafts_0218(owner_id,project_id,updated_at DESC);

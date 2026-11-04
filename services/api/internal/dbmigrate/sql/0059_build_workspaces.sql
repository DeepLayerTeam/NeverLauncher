-- Persist one complete, revision-checked workspace per operator/project.
-- Stage and build state is JSONB, but writes are guarded by revision CAS.
CREATE TABLE IF NOT EXISTS build_workspaces_0226 (
 id text PRIMARY KEY,
 project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 owner_id text NOT NULL,
 revision bigint NOT NULL CHECK (revision > 0),
 data jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT build_workspaces_data_object_0226 CHECK (jsonb_typeof(data) = 'object')
);
CREATE INDEX IF NOT EXISTS build_workspaces_owner_0226 ON build_workspaces_0226(project_id,owner_id,updated_at DESC);

-- 0.25.9: atomic administrative policy revisions, overrides and permanent audit.
ALTER TABLE texture_project_policies ADD COLUMN fallback_skin_digest TEXT REFERENCES texture_blobs(digest) ON DELETE RESTRICT;
ALTER TABLE texture_project_policies ADD COLUMN fallback_cape_digest TEXT REFERENCES texture_blobs(digest) ON DELETE RESTRICT;
ALTER TABLE texture_project_policies ADD COLUMN fallback_skin_model TEXT NOT NULL DEFAULT 'classic' CHECK (fallback_skin_model IN ('classic','slim'));
ALTER TABLE texture_project_policies ADD COLUMN default_skin_model TEXT NOT NULL DEFAULT 'classic' CHECK (default_skin_model IN ('classic','slim'));
ALTER TABLE texture_project_policies ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE texture_project_policies ADD COLUMN actor_user_id TEXT NOT NULL DEFAULT '';
ALTER TABLE texture_project_policies ADD COLUMN reason TEXT NOT NULL DEFAULT '';

CREATE TABLE texture_user_exceptions (
 project_id TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK (kind IN ('skin','cape')),
 decision TEXT NOT NULL CHECK (decision IN ('allow','deny')),
 actor_user_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(project_id,user_id,kind)
);
CREATE INDEX idx_texture_exceptions_user_0259 ON texture_user_exceptions(user_id,kind);
CREATE TABLE texture_policy_history (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 project_id TEXT NOT NULL,
 revision BIGINT NOT NULL,
 snapshot JSONB NOT NULL,
 actor_user_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(project_id,revision)
);
CREATE INDEX idx_texture_policy_history_project_0259 ON texture_policy_history(project_id,created_at DESC);
CREATE TABLE texture_exception_history (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 project_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 old_decision TEXT NOT NULL,
 new_decision TEXT NOT NULL,
 actor_user_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_texture_exception_history_project_0259 ON texture_exception_history(project_id,created_at DESC);

-- An explicit deny always overrides a permissive project-wide policy or old
-- cape grant. An explicit allow overrides a restrictive default. No override
-- preserves 0.25.8 behaviour, including legacy cape grants.
CREATE FUNCTION texture_permission_allowed_0259(p_project TEXT, p_user TEXT, p_kind TEXT)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT CASE
   WHEN (SELECT e.decision FROM texture_user_exceptions e
         WHERE e.project_id=p_project AND e.user_id=p_user AND e.kind=p_kind)='allow' THEN true
   WHEN (SELECT e.decision FROM texture_user_exceptions e
         WHERE e.project_id=p_project AND e.user_id=p_user AND e.kind=p_kind)='deny' THEN false
   WHEN p_kind='skin' THEN COALESCE((SELECT p.allow_player_skins FROM texture_project_policies p WHERE p.project_id=p_project),true)
   WHEN p_kind='cape' THEN COALESCE((SELECT p.allow_player_capes FROM texture_project_policies p WHERE p.project_id=p_project),false)
     OR COALESCE((SELECT c.granted FROM texture_cape_grants c WHERE c.project_id=p_project AND c.user_id=p_user),false)
   ELSE false END
$$;

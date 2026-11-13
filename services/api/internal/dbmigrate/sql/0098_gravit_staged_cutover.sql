-- MIG11: per-profile/channel Never release routing. One durable row owns the
-- cutover; a staged scope rejects concurrent writes to the channel head.
-- Source Gravit write fencing remains an explicit external prerequisite.
CREATE TABLE migration_cutovers_03311 (
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 profile_id TEXT NOT NULL,
 channel TEXT NOT NULL,
 stage_id TEXT NOT NULL,
 release_id TEXT NOT NULL REFERENCES release_versions(id) ON DELETE RESTRICT,
 release_version TEXT NOT NULL,
 target_digest CHAR(64) NOT NULL CHECK(target_digest ~ '^[a-f0-9]{64}$'),
 baseline_revision BIGINT NOT NULL CHECK(baseline_revision >= 0),
 baseline_release_id TEXT NOT NULL DEFAULT '',
 baseline_version TEXT NOT NULL DEFAULT '',
 baseline_digest TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL DEFAULT 'staged' CHECK(state IN ('staged','active','cancelled')),
 fence_reference TEXT NOT NULL DEFAULT '',
 fence_evidence_sha256 TEXT NOT NULL DEFAULT '',
 activated_revision BIGINT,
 revision BIGINT NOT NULL DEFAULT 1,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 activated_at TIMESTAMPTZ,
 PRIMARY KEY(project_id,profile_id,channel),
 UNIQUE(run_id,profile_id,channel),
 CHECK ((state='active') = (activated_revision IS NOT NULL)),
 CHECK (state<>'active' OR (char_length(fence_reference) BETWEEN 8 AND 256 AND fence_evidence_sha256 ~ '^[a-f0-9]{64}$'))
);
CREATE INDEX migration_cutovers_03311_run ON migration_cutovers_03311(run_id,created_at);

-- This trigger is installed on the actual read-through route used by
-- GetManifest. ALL existing channel publication code paths hit this table.
-- A staged scope blocks writes unless the matching MIG11 transaction holds
-- the session-local run marker. SET LOCAL resets automatically at COMMIT.
CREATE FUNCTION migration_channel_head_guard_03311() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE owner_run TEXT;
BEGIN
 IF TG_OP='UPDATE' AND (OLD.project_id<>NEW.project_id OR OLD.profile_id<>NEW.profile_id OR OLD.channel<>NEW.channel) THEN
  RAISE EXCEPTION 'migration route identity is immutable' USING ERRCODE='23514';
 END IF;
 SELECT run_id INTO owner_run FROM migration_cutovers_03311
 WHERE project_id=NEW.project_id AND profile_id=NEW.profile_id AND channel=NEW.channel AND state='staged';
 IF owner_run IS NOT NULL AND current_setting('never.migration_cutover_run',true) IS DISTINCT FROM owner_run THEN
  RAISE EXCEPTION 'migration cutover staged: channel writer fenced' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER migration_channel_head_guard_03311
BEFORE INSERT OR UPDATE ON channel_heads
FOR EACH ROW EXECUTE FUNCTION migration_channel_head_guard_03311();

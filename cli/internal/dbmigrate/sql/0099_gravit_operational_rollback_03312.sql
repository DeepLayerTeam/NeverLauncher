-- MIG12: retain one immutable rollback plan per activated channel. Planning
-- alone never mutates routing, worlds, player accounts or external Gravit.
CREATE TABLE migration_rollbacks_03312 (
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 project_id TEXT NOT NULL, profile_id TEXT NOT NULL, channel TEXT NOT NULL,
 plan_sha256 CHAR(64) NOT NULL CHECK(plan_sha256 ~ '^[a-f0-9]{64}$'),
 baseline_snapshot_sha256 CHAR(64) NOT NULL,
 current_snapshot_sha256 CHAR(64) NOT NULL,
 evidence_sha256 CHAR(64) NOT NULL,
 evidence_reference TEXT NOT NULL,
 route_revision BIGINT NOT NULL,
 state TEXT NOT NULL DEFAULT 'planned' CHECK(state IN ('planned','completed')),
 result JSONB NOT NULL,
 planned_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ,
 PRIMARY KEY(run_id,profile_id,channel),
 FOREIGN KEY(project_id,profile_id,channel) REFERENCES migration_cutovers_03311(project_id,profile_id,channel)
);
-- Both staged and activated channels remain protected; DELETE was missing in
-- MIG11 and could bypass its INSERT/UPDATE guard. A SET LOCAL marker may only
-- be used by the backend's transactional MIG11/MIG12 operation.
CREATE OR REPLACE FUNCTION migration_channel_head_guard_03311() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE owner_run TEXT; p TEXT; pr TEXT; ch TEXT;
BEGIN
 IF TG_OP='UPDATE' AND (OLD.project_id<>NEW.project_id OR OLD.profile_id<>NEW.profile_id OR OLD.channel<>NEW.channel) THEN
  RAISE EXCEPTION 'migration route identity is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN p:=OLD.project_id;pr:=OLD.profile_id;ch:=OLD.channel;
 ELSE p:=NEW.project_id;pr:=NEW.profile_id;ch:=NEW.channel; END IF;
 SELECT run_id INTO owner_run FROM migration_cutovers_03311
 WHERE project_id=p AND profile_id=pr AND channel=ch AND state IN ('staged','active');
 IF owner_run IS NOT NULL AND current_setting('never.migration_cutover_run',true) IS DISTINCT FROM owner_run THEN
  RAISE EXCEPTION 'migration cutover active: channel writer fenced' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER migration_channel_head_guard_03311 ON channel_heads;
CREATE TRIGGER migration_channel_head_guard_03311 BEFORE INSERT OR UPDATE OR DELETE ON channel_heads
FOR EACH ROW EXECUTE FUNCTION migration_channel_head_guard_03311();
ALTER TABLE migration_cutovers_03311 DROP CONSTRAINT IF EXISTS migration_cutovers_03311_state_check;
ALTER TABLE migration_cutovers_03311 ADD CONSTRAINT migration_cutovers_03311_state_check CHECK(state IN ('staged','active','cancelled','rolled_back'));
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='migration_cutovers_03311'::regclass
 AND contype='c' AND pg_get_constraintdef(oid) LIKE '%activated_revision%' LOOP
  EXECUTE format('ALTER TABLE migration_cutovers_03311 DROP CONSTRAINT %I',c.conname);
 END LOOP;
END $$;
-- MIG11 requires activated_revision only in active state; keep it for
-- rolled_back receipts so prior activation can be audited.
ALTER TABLE migration_cutovers_03311 ADD CONSTRAINT migration_cutovers_03311_activated_state_03312 CHECK
 ((state IN ('active','rolled_back')) = (activated_revision IS NOT NULL));

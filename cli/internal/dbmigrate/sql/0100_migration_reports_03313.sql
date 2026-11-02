-- MIG13: immutable operator review of an exact, server-generated consistent
-- snapshot. Review is NOT a GA certificate nor authorization for cutover.
CREATE TABLE migration_reports_03313 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 report_sha256 CHAR(64) NOT NULL CHECK(report_sha256 ~ '^[a-f0-9]{64}$'),
 report JSONB NOT NULL CHECK(jsonb_typeof(report)='object'),
 reviewed_by TEXT NOT NULL CHECK(char_length(reviewed_by) BETWEEN 1 AND 128),
 evidence_sha256 CHAR(64) NOT NULL CHECK(evidence_sha256 ~ '^[a-f0-9]{64}$'),
 evidence_reference TEXT NOT NULL CHECK(char_length(evidence_reference) BETWEEN 8 AND 256),
 reviewed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
-- Editing certified snapshots would invalidate their SHA-256 and audit chain.
CREATE OR REPLACE FUNCTION reject_migration_report_change_03313() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'migration RC review receipt is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER migration_report_immutable_03313 BEFORE UPDATE OR DELETE ON migration_reports_03313
FOR EACH ROW EXECUTE FUNCTION reject_migration_report_change_03313();

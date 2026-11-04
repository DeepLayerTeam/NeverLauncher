-- Operator-executed isolated rehearsal receipts. Reports store checksums and
-- sanitized evidence only, never staging credentials or unredacted logs.
CREATE TABLE migration_rehearsals_03310 (
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 stage_id TEXT NOT NULL CHECK(char_length(stage_id) BETWEEN 16 AND 128),
 inventory_sha256 CHAR(64) NOT NULL CHECK(inventory_sha256 ~ '^[a-f0-9]{64}$'),
 report_sha256 CHAR(64) NOT NULL CHECK(report_sha256 ~ '^[a-f0-9]{64}$'),
 report JSONB NOT NULL CHECK(jsonb_typeof(report)='object'),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(run_id,stage_id)
);

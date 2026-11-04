-- MIG08: source-bound static JAR review and ServerWrapper replacement enrollment intents.
-- Never store Gravit credentials, tokens, source JARs or private keys here.
CREATE TABLE migration_modules_0338 (
 run_id TEXT PRIMARY KEY REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 source_sha256 CHAR(64) NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
 inventory_sha256 CHAR(64) NOT NULL CHECK (inventory_sha256 ~ '^[a-f0-9]{64}$'),
 report JSONB NOT NULL CHECK (jsonb_typeof(report)='object'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE migration_wrapper_enrollments_0338 (
 run_id TEXT NOT NULL REFERENCES migration_runs_0331(id) ON DELETE RESTRICT,
 wrapper_path TEXT NOT NULL,
 server_id TEXT NOT NULL UNIQUE,
 public_key_fingerprint CHAR(64) NOT NULL CHECK (public_key_fingerprint ~ '^[a-f0-9]{64}$'),
 reserved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (run_id,wrapper_path)
);

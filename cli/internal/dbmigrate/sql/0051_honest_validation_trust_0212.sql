-- NeverLauncher 0.21.2 — честная проверка и явный границы доверия.
-- Целостность проверяет и свидетельство реального запуска являются независимый долговременный записывает.

CREATE TABLE IF NOT EXISTS package_integrity_checks (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES release_versions(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    manifest_digest TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    signature_verified BOOLEAN NOT NULL,
    storage_verified BOOLEAN NOT NULL,
    files_verified BOOLEAN NOT NULL,
    compatibility_verified BOOLEAN NOT NULL,
    result TEXT NOT NULL,
    checks JSONB NOT NULL DEFAULT '[]'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT package_integrity_manifest_digest_0212 CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT package_integrity_artifact_digest_0212 CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT package_integrity_result_0212 CHECK (result IN ('passed','failed'))
);
CREATE INDEX IF NOT EXISTS idx_package_integrity_latest_0212 ON package_integrity_checks(package_id,checked_at DESC);

CREATE TABLE IF NOT EXISTS package_runtime_validations (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES release_versions(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    manifest_digest TEXT NOT NULL,
    target_id TEXT NOT NULL,
    minecraft_version TEXT NOT NULL DEFAULT '',
    loader TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    java_runtime TEXT NOT NULL DEFAULT '',
    actual_client BOOLEAN NOT NULL DEFAULT false,
    exit_code INTEGER NOT NULL DEFAULT 0,
    server_join BOOLEAN NOT NULL DEFAULT false,
    run_id TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    evidence_hashes JSONB NOT NULL DEFAULT '{}'::jsonb,
    signer_key_id TEXT NOT NULL,
    signer_key_fingerprint TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    result TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT package_runtime_manifest_digest_0212 CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT package_runtime_signer_fingerprint_0212 CHECK (signer_key_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT package_runtime_evidence_digest_0212 CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT package_runtime_result_0212 CHECK (result IN ('passed','failed')),
    CONSTRAINT package_runtime_window_0212 CHECK (finished_at >= started_at),
    CONSTRAINT package_runtime_pass_truth_0212 CHECK (result <> 'passed' OR (actual_client AND exit_code=0))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_package_runtime_run_target_0212 ON package_runtime_validations(package_id,run_id,target_id) WHERE run_id<>'';
CREATE INDEX IF NOT EXISTS idx_package_runtime_latest_0212 ON package_runtime_validations(package_id,finished_at DESC);

CREATE TABLE IF NOT EXISTS project_validation_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    required_level TEXT NOT NULL DEFAULT 'integrity',
    require_server_join BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT project_validation_level_0212 CHECK (required_level IN ('integrity','runtime'))
);
INSERT INTO project_validation_policies(project_id,required_level,require_server_join)
SELECT id,'integrity',false FROM projects ON CONFLICT(project_id) DO NOTHING;

-- Устаревший smoke состояние представленный file/storage проверка только. Preserve 
-- пакет как подготовленный так это должен obtain канонический целостность запись до 
-- следующий публикация попытка; уже-опубликованный релизы оставаться неизменяемый.
UPDATE release_versions SET status='staged',updated_at=now() WHERE status IN ('smoke-passed','smoke-failed');

-- Существующий запрос-ответ свидетельство доказывает ключ possession/local привязка,
-- не удалённый TPM/Защищённый-Анклав происхождение. Нет миграция elevates уверенность.
ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS remote_hardware_provenance TEXT NOT NULL DEFAULT 'not-verified';
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_remote_hardware_provenance_0212;
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_remote_hardware_provenance_0212
    CHECK (remote_hardware_provenance IN ('not-verified','verified')) NOT VALID;
ALTER TABLE trusted_devices VALIDATE CONSTRAINT trusted_devices_remote_hardware_provenance_0212;

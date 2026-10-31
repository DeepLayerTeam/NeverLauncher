-- NeverLauncher 0.13.10: миграция Guard, совместимость и стабилизация.
--
-- В 0.13.5 сохранялся снимок целостности Guard в minecraft_sessions,
-- но первая схема ограничивала только отдельные хеши. Теперь
-- состояние атомарно: строка либо устаревшая/без Guard и без
-- снимка, либо содержит полный проверенный сервером снимок
-- Guard для текущей авторизации Minecraft/ServerBridge.
--
-- При неоднозначных строках до обновления отказывайте. Молчаливое
-- создание или удаление частичного снимка безопасности изменило
-- бы смысл авторизации уже выданных данных Minecraft.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM minecraft_sessions
        WHERE integrity_verified = TRUE
          AND (
            trusted_device_id IS NULL OR
            guard_attestation_sha256 !~ '^[0-9a-f]{64}$' OR
            guard_evidence_sha256 !~ '^[0-9a-f]{64}$' OR
            guard_sha256 !~ '^[0-9a-f]{64}$' OR
            launcher_sha256 !~ '^[0-9a-f]{64}$' OR
            btrim(launcher_version) = '' OR
            launcher_version <> btrim(launcher_version) OR
            char_length(launcher_version) > 64 OR
            integrity_verified_at IS NULL OR
            created_at IS NULL OR
            integrity_verified_at > created_at + interval '15 seconds' OR
            created_at - integrity_verified_at > interval '105 seconds'
          )
    ) THEN
        RAISE EXCEPTION '0.13.10 migration: integrity_verified minecraft session has incomplete or stale Guard snapshot';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM minecraft_sessions
        WHERE integrity_verified = FALSE
          AND (
            btrim(guard_attestation_sha256) <> '' OR
            btrim(guard_evidence_sha256) <> '' OR
            btrim(guard_sha256) <> '' OR
            btrim(launcher_sha256) <> '' OR
            btrim(launcher_version) <> '' OR
            integrity_verified_at IS NOT NULL
          )
    ) THEN
        RAISE EXCEPTION '0.13.10 migration: non-verified minecraft session carries partial Guard snapshot';
    END IF;
END $$;

ALTER TABLE minecraft_sessions
    DROP CONSTRAINT IF EXISTS minecraft_sessions_guard_snapshot_shape_01310,
    ADD CONSTRAINT minecraft_sessions_guard_snapshot_shape_01310 CHECK (
        (
            integrity_verified = FALSE AND
            guard_attestation_sha256 = '' AND
            guard_evidence_sha256 = '' AND
            guard_sha256 = '' AND
            launcher_sha256 = '' AND
            launcher_version = '' AND
            integrity_verified_at IS NULL
        ) OR (
            integrity_verified = TRUE AND
            trusted_device_id IS NOT NULL AND
            guard_attestation_sha256 ~ '^[0-9a-f]{64}$' AND
            guard_evidence_sha256 ~ '^[0-9a-f]{64}$' AND
            guard_sha256 ~ '^[0-9a-f]{64}$' AND
            launcher_sha256 ~ '^[0-9a-f]{64}$' AND
            launcher_version = btrim(launcher_version) AND
            char_length(launcher_version) BETWEEN 1 AND 64 AND
            integrity_verified_at IS NOT NULL
        )
    );

ALTER TABLE minecraft_sessions
    DROP CONSTRAINT IF EXISTS minecraft_sessions_guard_snapshot_freshness_01310,
    ADD CONSTRAINT minecraft_sessions_guard_snapshot_freshness_01310 CHECK (
        integrity_verified = FALSE OR (
            integrity_verified_at <= created_at + interval '15 seconds' AND
            created_at - integrity_verified_at <= interval '105 seconds'
        )
    );

CREATE INDEX IF NOT EXISTS idx_minecraft_sessions_guard_verified_device_01310
    ON minecraft_sessions(trusted_device_id, launcher_version, integrity_verified_at DESC)
    WHERE integrity_verified = TRUE;

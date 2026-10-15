-- NeverLauncher 0.16.1: завершение схемы назначений запросов Guard Attestation.
--
-- Guard Attestation 0.13.4 добавила два одноразовых назначения в device_challenges:
-- guard-attest-v1 для доказательства вызов–ответ и guard-launch-v1 для
-- короткого билета запуска, используемого аутентификацией Minecraft. Пути
-- HTTP и репозитория существуют с 0.13.4, но CHECK-ограничение PostgreSQL
-- последний раз пересоздавалось в 0.12.10 и отклоняло оба значения.
--
-- Миграция лишь расширяет перечисление допустимых назначений. Она не ослабляет
-- сроки запросов, принадлежность, однократное погашение, проверку подписей,
-- список разрешённых выпусков и другие инварианты Guard/Device Trust.

ALTER TABLE device_challenges
    DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;

ALTER TABLE device_challenges
    ADD CONSTRAINT device_challenges_purpose_check
    CHECK (purpose IN (
        'register',
        'session-bind',
        'attest',
        'key-rotate',
        'key-recover',
        'guard-attest-v1',
        'guard-launch-v1'
    ));

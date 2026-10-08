-- NeverLauncher 0.16.1 — Защита Аттестация запрос-назначение схема завершение.
--
-- Защита Аттестация 0.13.4 добавленный два одноразовый запрос назначение основанный через
-- устройство_запросы: защита-attest-v1 для challenge/response доказательство и
-- защита-запускать-v1 для краткоживущий запускать билет использованный через Minecraft аутентификация.
-- HTTP/репозиторий пути имеют поставляемый since 0.13.4, но PostgreSQL CHECK
-- ограничение был последний пересобран через 0.12.10 и поэтому отклонён оба значения.
--
-- Этот миграция только widens enumerated назначение задать. Это делает не weaken
-- запрос истечение, владение, одноразовый consumption, подпись проверка,
-- релиз список разрешений, или любой другой Guard/Device Доверие безопасность инвариант.

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

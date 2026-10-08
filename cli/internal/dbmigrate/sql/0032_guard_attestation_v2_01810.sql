-- NeverLauncher 0.18.10 — Защита Аттестация v2 challenge/ticket назначение.
--
-- Аттестация v2 является намеренно после запуска на Windows: актуальный запрос является
-- завершённый только после NeverGuard Sensor и Непрерывный Защита являются активный. 
-- результат краткоживущий билет является использованный точно один раз через ServerBridge подключение.
-- Существующий v1 инициализировать назначение оставаться действительный для Minecraft-сессия выдача.

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
        'guard-launch-v1',
        'guard-attest-v2',
        'guard-continuous-join-v2'
    ));

-- Launcher 0.18.10: назначения запросов и разрешений Guard Attestation v2.
--
-- В Windows аттестация v2 намеренно проходит после запуска: новый запрос выполняется,
-- только когда активны Guard Sensor и Continuous Guard. Полученный короткий
-- билет однократно погашается при входе ServerBridge. Старые назначения первоначальной
-- инициализации v1 остаются допустимыми для выдачи сеансов Minecraft.

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

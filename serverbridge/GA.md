# ServerBridge 3 GA — NeverLauncher 0.20.0

ServerBridge 3 является GA в NeverLauncher 0.20.0. Протокол v3 является зафиксированный: канонический набор возможностей хеш является `098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc`. Протокол v2 остаётся принят через Серверная часть только как `compatibility-deprecated`; новый 0.20.0 мост согласовывать v3 только.

## Рабочий миграция v2 → v3

1. Применить база данных миграция `0041_serverbridge3_ga_0200` с `nl db migrate apply`, затем проверять это с `nl db migrate verify`.
2. Сохранять 0.20.0 Серверная часть работоспособный и проверять `GET /api/v1/server-bridge/capabilities` сообщает `protocolV3Frozen=true`, `protocolV3Status=ga-frozen` и зафиксированный хеш выше.
3. Для каждый управляемый узел запуск `nl server-bridge migrate-v3 --server-dir <dir> --artifacts-dir <release-artifacts>`. команда выполняет обычный сертифицированный транзакционный обновление, сохраняет Ed25519 узел идентичность, поддерживает `--dry-run`, и записывает `.neverlauncher/server-bridge/protocol-v3-ga-migration.json` после успех.
4. Перезапуск Minecraft/proxy процесс когда отображается через установщик. Confirm узел appears как Протокол v3 в `GET /api/v1/server-bridge/overview`.
5. Сохранять Протокол v2 только для оставаться устаревший узлы. v2 ответы carry deprecation/migration заголовки и Панель администратора счётчики узлы по-прежнему требовать миграция.

 миграция делает не patch Minecraft/authlib/core. Откат остаётся существующий `nl server-bridge rollback` путь и восстанавливает предыдущий управляемый мост artifact/state пока сохраняя узел идентичность.

## Сертификация и установка

 GA релиз является действительный только когда `SERVERBRIDGE3_CERTIFICATION.json` имеет схема `1.1`, `ga=true`, `protocolV3Frozen=true`, точный зафиксированный возможность хеш, `protocolV2Mode=compatibility-deprecated`, `installerUpgradePath=true`, `unifiedOperatorAPI=/api/v1/server-bridge/overview`, и хеширует для все 14 поддерживаемый артефакты. `BRIDGE_RELEASE_ALLOWLIST.json` остаётся схема `3.0` и содержит одинаковый GA протокол политика плюс профиль безопасности и точный на-платформа SHA-256 значения.

`nl server-bridge install`, `upgrade`, и `migrate-v3` отклонять 0.20.x артефакт чей certification/allowlist делает не satisfy этот GA граница если не явный разработка-только unverified override является используется.

## Оператор API и Панель администратора

`GET /api/v1/server-bridge/overview` является единый аутентифицировать оператор view для топология, управление история, последний телеметрия, node/runtime состояние, Протокол v2 миграция состояние, обновление recommendations, и ServerBridge события аудита. Панель администратора использовать этот эндпоинт напрямую.

 публичный матрица совместимости является `GET /api/v1/server-bridge/matrix` и `serverbridge/MATRIX.md`. Это список все 14 релиз цели и явно marks Протокол v3 как GA/frozen и Протокол v2 как compatibility/deprecated.

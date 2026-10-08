# Production-развёртывание NeverLauncher

Production-стек использует PostgreSQL, Redis с паролем, Серверная часть API, неизменяемый образ Администратор и Nginx входной трафик. Проверка совместимости БД, доверие к манифестам и распределённый ограничение частоты работают отказ с блокировкой.

### Обновление 0.19.1 → 0.19.2 — обнаружение узла и Среда выполнения Идентичность

Перед развёртывание создайте резервное копирование и примените `0033_serverbridge_runtime_identity_0192`, затем выполните `nl db migrate verify`. Миграция добавляет текущий среда выполнения состояние и append-style среда выполнения история; существующие Ed25519 узел идентичности, Протокол v2/v3 подключение билеты и топология состояние не сбрасываются.

Сначала обновите Серверная часть до 0.19.2. Мост 0.19.1 продолжит работать по Протокол v3 без среда выполнения возможность пара. Затем обновляйте соответствующий платформе мост JAR до 0.19.2 по одному: возможности согласование включит `runtime.node-discovery-v1` и `security.runtime-identity-ed25519`, после чего сигнал состояния начнёт отправлять узел-привязанный подписанный среда выполнения дескриптор. Проверьте в узел диагностика `runtimeId`, `runtimeEpoch`, Minecraft/Java/loader/brand метаданные и переход `started`/`unchanged`. При штатном JVM перезапуск после истечения актуальность ожидается `restart`; одновременный новый JVM при свежем предыдущем сигнал состояния фиксируется как `replacement` и событие аудита.

### Обновление 0.19.0 → 0.19.1 — ServerBridge 3

Примените миграция `0031_serverbridge_protocol_v3_0191`, затем выполните `nl db migrate verify`. Она расширяет существующие node/join ограничения до Протокол v2/v3 и не сбрасывает Ed25519 идентичности: старые 0.19.0 мост продолжают работать по v2 во время поэтапный обновление.

Сначала обновите Серверная часть до 0.19.1, затем заменяйте мост JAR по одному. Мост 0.19.1 запрашивает `GET /api/v1/server-bridge/capabilities`, выбирает Протокол v3 и передаёт согласовывать набор возможностей в heartbeat/validate-join/handoff. Единственный автоматический понижение версии к v2 разрешён при HTTP 404 от старого Серверная часть; ошибки согласование и 5xx остаются отказ с блокировкой. После развёртывание проверьте диагностика (`protocolVersion=3`, `supportedProtocolVersions=[3,2]`), публичная матрица и `SERVERBRIDGE3_CERTIFICATION.json`.

### Обновление 0.15.9 → 0.15.10

DB миграция не требуется. Перед развёртывание сохраните резервное копирование установка корень и постоянный релиз доверие состояние. На каждом установка выполните `nl update migrate-state --root <install>` либо позвольте первому `update recover/components` выполнить миграция автоматически: устаревший macOS `.neverlauncher/updater/component-update-state.json` будет перенесён в канонический `.neverlauncher/component-update-state.json`, неполный транзакция восстановлены, а конечный staging/backup очищены после долговременный журнал.

Постоянный релиз доверие состояние остаётся внешним по отношению к комплект релиза. Первый успешный `nl release verify` 0.15.10 под `<trust-state>.lock` мигрирует схема 2.0 → 2.1 и фиксирует SHA-256 принятого `RELEASE_MANIFEST.json`. Не удаляйте `highestReleaseManifestSha256`/`stateRevision` вручную и не размещайте доверие состояние внутри релиз каталог. Если миграция сообщает конфликт одинаковой компонент версия с разными хеширует, остановите развёртывание и сравните установка с последним проверенным рабочий пакет.

Проверка перед развёртывание:

```bash
nl update migrate-state --root /opt/neverlauncher
nl update stabilization-self-test
nl release verify dist/release-0.15.10 \
  --public-key /etc/neverlauncher/root-public.pem \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/release-trust-state.json
```

### Обновление 0.14.10 → 0.15.0

`0.15.0` не добавляет новую DB миграция: перед развёртывание `nl db migrate verify` должен подтверждать запечатанный `0030_serverbridge_migration_stabilization_01410`. Соберите все 11 мост JAR через `scripts/build/bridge-plugins.sh`; сборка должна создать `SERVERBRIDGE2_CERTIFICATION.json`, который связывает точный `0.15.0` матрица, манифест, SHA256SUMS и `BRIDGE_RELEASE_ALLOWLIST.json`.

В рабочий установите соответствующий платформе `0.15.0` JAR и точный хеширует из релиз список разрешений. Финальный комплект обязан содержать `SERVERBRIDGE2_CERTIFICATION.json`; `nl release publish-check` повторно сверяет hashes/sizes всех 11 JAR и отклоняет неполный или смешанный релиз группа.

### Обновление 0.14.9 → 0.14.10

Остановите 0.14.9 API реплики, создайте проверенный резервное копирование и примените `0030_serverbridge_migration_stabilization_01410` через `nl db migrate apply`, затем выполните `nl db migrate verify`. Текущий миграция должна быть `0030_serverbridge_migration_stabilization_01410` до запуска 0.14.10 Серверная часть.

Миграция не меняет ServerBridge Протокол v2 и не переписывает узел Ed25519 идентичности, релиз-целостность состояние или ещё действующие tickets/handoffs. Она seal-ит только уже expired/stale временный строки и добавляет индексы под среда выполнения lookup/retention. После развёртывание обслуживание выполняет ограниченный строка пакеты через `FOR UPDATE SKIP LOCKED`; конечный история очищается ограниченно, при этом использованный подключение сохраняется пока его аутентификация сессия активна, чтобы прокси→серверная часть передача не терял исходник доказательство. Проверьте `/ready`, ServerBridge диагностика и точный 0.14.9→0.14.10 миграция E2E.

### Обновление 0.14.8 → 0.14.9

Перед развёртывание остановите старые 0.14.8 API экземпляры, создайте проверенный резервное копирование и примените `0029_serverbridge_public_matrix_ha_hardening_0149`, затем выполните `nl db migrate verify`. Миграция сохраняет узел идентичности, подключение билеты, передачи и топология, добавляя индексы для freshness/HA обслуживание.

В рабочий оставьте `NEVERLAUNCHER_RATE_LIMIT_ENABLED=true`, `NEVERLAUNCHER_RATE_LIMIT_FAIL_CLOSED=true` и доступный `NEVERLAUNCHER_REDIS_URL`; ServerBridge получает отдельный распределённый budget `NEVERLAUNCHER_RATE_LIMIT_SERVERBRIDGE_PER_MINUTE` (по умолчанию 6000/min). После запуска проверьте `/ready`, ServerBridge метрики, `GET /api/v1/server-bridge/matrix` и внутренний диагностика. Топология edge считается `active` только при свежем edge и сигнал состояния обоих узлов; устаревший состояние больше не выдаётся как актуальный. Истёкший nonces/tickets/handoffs очищаются HA-безопасный обслуживание под PostgreSQL рекомендательный блокировка, а одноразовое значение hot путь не выполняет таблица-wide очистка.

### Обновление 0.14.7 → 0.14.8

Остановите 0.14.7 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0028_zero_patch_topology_handoff_0148` до запуска 0.14.8 Серверная часть. Миграция сохраняет существующие ServerBridge nodes/tickets и добавляет PostgreSQL исходник--truth для среда выполнения топология и прокси→серверная часть передача.

Обновите мост артефакты до 0.14.8 и сохраните обычную конфигурацию платформы: NeverLauncher не патчит `server.properties`, Bukkit/Paper/Folia конфигурация, Fabric/Forge/NeoForge конфигурация или Velocity/BungeeCord/Waterfall маршрутизация. Прокси после успешного лаунчер вход выпускает подписанный одноразовый передача только при фактическом выборе серверная часть; серверная часть повторно проверяет trust/integrity и атомарно consume-ит передача. Ed25519 узел регистрация и точный релиз SHA-256 список разрешений по-прежнему обязательны. После развёртывание проверьте `GET /api/v1/server-bridge/topology`, затем прокси→серверная часть разрешать и повторный повторное воспроизведение запрещать.

### Обновление 0.14.6 → 0.14.7

Остановите 0.14.6 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0027_forge_neoforge_server_bridge_0147` до запуска 0.14.7 Серверная часть. Миграция расширяет только канонический ServerBridge тип ограничение и сохраняет существующие identities/tickets.

Соберите `scripts/build/bridge-plugins.sh`, установите `neverlauncher-forge-bridge-0.14.7.jar` или `neverlauncher-neoforge-bridge-0.14.7.jar` строго на соответствующую платформу, добавьте `forgeSha256`/`neoforgeSha256` из `BRIDGE_RELEASE_ALLOWLIST.json`, зарегистрируйте канонический тип и регистрировать публичный Ed25519 ключ. Затем проверьте сигнал состояния и `allow → replay deny → revoke → deny`.

### Обновление 0.14.5 → 0.14.6

Остановите 0.14.5 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0026_fabric_server_bridge_0146` до запуска 0.14.6 Серверная часть. Миграция только расширяет ServerBridge тип ограничение и сохраняет существующие узел identities/tickets.

Соберите `scripts/build/bridge-plugins.sh`, установите `neverlauncher-fabric-bridge-0.14.6.jar` в `/mods` Fabric 1.21.1 сервер вместе с Fabric API и добавьте `fabricSha256` из `BRIDGE_RELEASE_ALLOWLIST.json` в рабочий политика. Зарегистрируйте `kind=fabric`, регистрировать публичный Ed25519 ключ и проверьте сигнал состояния плюс разрешать → повторное воспроизведение запрещать → отзыв → запрещать. Клиентский NeverLauncher/Fabric мод для этого мост не требуется.

### Обновление 0.14.4 → 0.14.5

Остановите 0.14.4 API экземпляры, примените `nl db migrate apply` и убедитесь через `nl db migrate verify`, что текущий миграция — `0025_proxy_family_0145`. Обновите релиз список разрешений точными SHA-256 `velocity/bungeecord/waterfall/bukkit/spigot/paper/purpur/folia`, установите соответствующий платформе прокси JAR и дождитесь подписанный сигнал состояния каждого узел. BungeeCord/Waterfall используют отдельные узел идентичности; закрытый Ed25519 ключи остаются только на соответствующем прокси.


## Запуск

```bash
cp deploy/production/env.production.example deploy/production/.env.production
# замените все значения CHANGE_ME
docker compose --env-file deploy/production/.env.production -f deploy/production/docker-compose.yml build
docker compose --env-file deploy/production/.env.production -f deploy/production/docker-compose.yml up -d
```

Образ Администратор собирается из `apps/admin/Dockerfile`; каталог `apps/admin/dist` на хост не требуется.

## База данных и первичная инициализация

`NEVERLAUNCHER_DATABASE_AUTO_MIGRATE=true` применяет встроенную цепочку production-миграций под PostgreSQL рекомендательный блокировка. Если автоматический-мигрировать отключён, примените миграции явно через `nl db migrate apply`; API откажется запускаться или переходить в готовность при pending-миграциях либо несовпадении контрольная сумма.


### Обновление 0.14.3 → 0.14.4

Остановите 0.14.3 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0024_bukkit_family_0144` до запуска 0.14.4 Серверная часть. Миграция сохраняет существующие Velocity/Paper/Purpur узлы и расширяет допустимый `kind` на Bukkit/Spigot/Folia.

Соберите `scripts/build/bridge-plugins.sh` и установите JAR, соответствующий фактической платформе узел: `bukkit`, `spigot`, `paper`, `purpur` или `folia`. Обновите `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` из нового `BRIDGE_RELEASE_ALLOWLIST.json`: для 0.14.4 рабочий политика обязательны отдельные хеширует Bukkit/Spigot/Paper/Purpur/Folia и Velocity. Folia узел должен использовать Folia JAR с `folia-supported: true`; платформа несоответствие отключается отказ с блокировкой. После развёртывание проверьте сигнал состояния и подписанный allow/revoke/deny вход поток каждого типа.

### Обновление 0.14.2 → 0.14.3

Остановите 0.14.2 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0023_one_time_join_tickets_0143` до запуска 0.14.3 Серверная часть.

Миграция намеренно отказ с блокировкой инвалидирует оставшиеся активный ServerBridge билеты 0.14.2 и очищает временный `minecraft_joins`: старые записи не содержат идентичность binding/redemption доказательство и не могут считаться доказанно одноразовыми. После запуска выдайте свежий подключение и проверьте, что он имеет `ticketVersion=2`, привязан к текущему Ed25519 `identity_epoch/key_fingerprint`, первый подписанный проверять переводит билет в `consumed`, а повторное воспроизведение отклоняется. Для Yggdrasil совместимости первый валидный `/hasJoined` также должен consume-ить авторизация, повторный — возвращать отсутствие подключение.

### Обновление 0.14.1 → 0.14.2

Остановите 0.14.1 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0022_serverbridge_crypto_node_identities_0142` до запуска 0.14.2 Серверная часть.

Миграция отказ с блокировкой выводит прежние активный ServerBridge узлы из эксплуатации: bearer хеширует очищаются, статус становится `identity-enrollment-required`, незавершённые подключение билеты инвалидируются. Установите мост плагин 0.14.2 на каждом Velocity/Paper/Purpur узел; при первом старте он локально создаст Ed25519 `node-identity.properties` и выведет только публичный key/fingerprint. Передавайте Серверная часть только открытый ключ и выполните административный `POST /api/v1/server-bridge/servers/{serverId}/rotate-identity` с `{"keyAlgorithm":"ed25519","publicKey":"..."}`. Закрытый ключ не копируется в Backend/env и должен оставаться на узел. После регистрация проверьте сигнал состояния, целостность измерение и подписанный проверять-подключение.

### Обновление 0.14.0 → 0.14.1

Остановите 0.14.0 API экземпляры, создайте проверенный резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Текущий миграция должна быть `0021_serverbridge_protocol_v2_0141` до запуска 0.14.1 Серверная часть.

Миграция переносит устаревший ServerBridge metadata/textures из последнего сохранённый снимок, но не может восстановить сервер учётные данные хеш и активный подключение bearer хеш, которые 0.14.0 намеренно не сериализовал. Такие узлы помечаются `credential-rotation-required`; после запуска 0.14.1 ротируйте сервер токен административным эндпоинт и обновите токен в конфигурации соответствующего Velocity/Paper/Purpur мост. Мост плагин должен быть 0.14.1 и отправлять Протокол v2.

### Обновление 0.13.9 → 0.13.10

Остановите 0.13.9 API экземпляры, проверьте резервное копирование и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"` до запуска 0.13.10 Серверная часть. Миграция `0020_guard_migration_compatibility_stabilization_01310` намеренно отказ с блокировкой отклоняет partial/ambiguous сохранённый Защита снимки; не удаляйте ограничения и не подменяйте контрольная сумма. Исправьте конкретные устаревший строки на копии БД, повторите репетиция `e2e/scripts/run-guard-migration-e2e.sh`, затем повторите рабочий обновление.

После обновление `GET /ready` должен подтверждать текущий миграция `0020_guard_migration_compatibility_stabilization_01310`. Для Защита сертификация релиза на-платформа результат обязан быть связан с тем же repository/commit/run, что агрегат матрица.

### Доверие к устройству Релиз 0.13.0

`0.13.0` не добавляет новую DB миграция: перед запуском API `nl db migrate verify` должен подтверждать `0018_device_trust_stabilization_01210`. Для официальной публикации комплект релиза задайте `NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE`, `NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE` и `NEVERLAUNCHER_SOURCE_COMMIT`; `nl release publish-check` отказ с блокировкой проверит обе сертификация для точный фиксация. Комплект без публичный matrices является кандидат в релиз, а не готовый к публикации Доверие к устройству Релиз.

### Обновление 0.12.9 → 0.12.10

Перед обновлением существующей `0.12.9` БД создайте и проверьте резервное копирование, затем остановите старые API экземпляр, чтобы они не писали Доверие к устройству состояние параллельно миграция. Примените `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"` и сразу `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"` до запуска `0.12.10` API. Миграция `0018_device_trust_stabilization_01210` отказ с блокировкой остановится при межпользовательский/структурно противоречивых Доверие к устройству связях; не обходите ошибку ручным удалением ограничения — восстановите/исправьте данные из проверенного резервное копирование и повторите обновление.

Для репетиция на копии рабочий схема используйте `e2e/scripts/run-device-trust-migration-e2e.sh`: релиз CI строит точный `0.12.9` схема (`0001..0017`) и требует подтверждённый переход на `0018`.

Для новой установки:

1. Задайте сильный одноразовый `NEVERLAUNCHER_BOOTSTRAP_TOKEN`.
2. Запустите стек.
3. Вызовите `POST /api/v1/install/bootstrap-admin` с `X-NeverLauncher-Bootstrap-Token`.
4. Авторизуйтесь и создайте первый проект через `POST /api/v1/install/first-project`.
5. После установки `installation_completed` удалите инициализировать токен из окружения развёртывание.

## Redis ограничение частоты

Compose формирует `NEVERLAUNCHER_REDIS_URL` из `REDIS_PASSWORD`. Рабочий ограничение частоты распределённый и отказ с блокировкой: отказ Redis приводит к ошибке запуска/готовность вместо скрытого перехода на на-процесс ограничитель. Redis не публикуется на хост.

## Доверенные прокси

Compose-сеть использует фиксированный внутренний CIDR. Заголовки `X-Forwarded-For` и `X-Real-IP` принимаются только от явно доверенных прокси. Заголовки от недоверенных узлов игнорируются. Не задавайте публичную Internet-сеть в `NEVERLAUNCHER_TRUSTED_PROXY_CIDRS`.

## TLS

Встроенный входной трафик использует только HTTP и рассчитан на работу за реальным TLS эндпоинт. Публичное развёртывание обязано использовать HTTPS и `NEVERLAUNCHER_PUBLIC_URL=https://...`. Настройки TLS 1.2/1.3, HSTS и прокси заголовки описаны в [`TLS.md`](./TLS.md).

## Хранилище

Перед стартом API одноразовый `api-volume-init` выставляет UID/GID `10001:10001` для именованный тома storage/backups; сам API остаётся непривилегированным пользователем `neverlauncher`. Это работает и для уже существующих корень-принадлежащий тома.

Локальный хранилище монтируется в `/var/lib/neverlauncher/storage`, а резервное копирование — отдельно в `/var/lib/neverlauncher/backups`. S3-compatible драйвер записывает входящий поток во временный файл с ограниченным размером, параллельно вычисляет SHA-256 и затем отправляет файл в S3. Ошибка инициализации или работоспособность-проверка S3 останавливает API; резервный вариант на локальный хранилище отсутствует.

## CORS и резервное копирование

Задайте `NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` явным списком HTTPS источник. Маска `*` в рабочий отклоняется при старте. `NEVERLAUNCHER_BACKUP_ROOT` обязан быть отделён от локальный хранилище. Резервное копирование включает PostgreSQL dump и фактические storage-объекты; destructive восстановление требует точного подтверждения резервное копирование ID.

## Проверка состояния

```bash
curl -fsS http://127.0.0.1/health
curl -fsS http://127.0.0.1/ready
```

`/ready` включает совместимость миграций PostgreSQL и состояние Redis ограничитель.

## Релизные проверки

```bash
python3 scripts/contracts/validate-openapi.py
export NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE=/secure/release-private.pem
export NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE=/etc/neverlauncher/root-public.pem
export NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE=/secure/RELEASE_TRUST_POLICY.json
export NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE=/var/lib/neverlauncher/release-trust-state.json
export NEVERLAUNCHER_PUBLIC_RELEASE_BASE_URL="https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v$(cat VERSION)"
bash scripts/release/build-release.sh
NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh
```

`.github/workflows/ci.yml` — обязательный CI: репозиторий политика, Go race/vet/build, Admin/Desktop, Rust fmt/clippy/test/build, Tauri, реальные ServerBridge, production-контейнеры и PostgreSQL/Redis/Velocity/Spigot/Paper/Purpur/Folia/Fabric/Forge/NeoForge E2E должны пройти успешно.

### ServerBridge HA Плоскость управления 0.19.11

Для нескольких API реплики используйте общие PostgreSQL и Redis. На каждой реплика задайте уникальный `NEVERLAUNCHER_REPLICA_ID`; `NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED=true` запрещает локальный резервный вариант для управление владение. ServerBridge получает несколько HTTPS источник через `backend.urls` или `NEVERLAUNCHER_BACKEND_URLS`; transport/502/503/504 допускают failover, а authentication/authorization отклонение не переключается на другой эндпоинт. Перед поэтапный развёртывание примените миграция `0040_serverbridge_ha_control_plane_01911`.
### ServerBridge Безопасность и Сертификация 0.19.12

Мост 0.19.12 использует только Протокол v3 профиль безопасности `serverbridge3-security-01912`; старый Протокол v2 остаётся на Серверная часть только для уже развёрнутого fleet. Рабочий релиз должен использовать ServerBridge 3 список разрешений схема 3.0 с точным возможность хеш и всеми 14 платформа SHA-256.

Для ротации управление ключ подписи без downtime сначала оставьте текущий начальное значение в `NEVERLAUNCHER_SERVERBRIDGE_CONTROL_PREVIOUS_SIGNING_PRIVATE_KEY`, а новый начальное значение установите в `NEVERLAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY`. Выполните поэтапный развёртывание Серверная часть, дождитесь, пока активные Мост успешно согласовывать возможность документ с перекрытие ключ-задать, и только затем удалите предыдущий ключ и повторите поэтапный развёртывание. После финализации удалённый ключ больше не считается якорь доверия. Не используйте одинаковый active/previous начальное значение.


### ServerBridge 3 GA 0.20.0

Перед развёртывание примените `0041_serverbridge3_ga_0200`, затем обновите Серверная часть до 0.20.0. Протокол v3 заморожен; Протокол v2 остаётся только в compatibility/deprecation режим. Для каждого управляемый узел сначала выполните `nl server-bridge migrate-v3 --dry-run --server-dir <dir> --artifacts-dir <release>`, затем повторите без `--dry-run`. Команда требует GA возможности Серверная часть и сертифицированный 0.20.0 артефакт, сохраняет узел Ed25519 идентичность и использует существующий транзакционный upgrade/rollback путь. После рестарта проверяйте `/api/v1/server-bridge/overview`: узел должен иметь Протокол v3/`ga-frozen`, а счётчик `protocolMigrationsRequired` должен уменьшиться.

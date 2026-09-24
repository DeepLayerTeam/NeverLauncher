# Production-развёртывание NeverLauncher

Production-стек использует PostgreSQL, Redis с паролем, Backend API, неизменяемый образ Admin и Nginx ingress. Проверка совместимости БД, доверие к манифестам и распределённый rate limiting работают fail-closed.

### Upgrade 0.14.6 → 0.14.7

Остановите 0.14.6 API instances, создайте проверенный backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Current migration должна быть `0027_forge_neoforge_server_bridge_0147` до запуска 0.14.7 Backend. Migration расширяет только canonical ServerBridge kind constraint и сохраняет существующие identities/tickets.

Соберите `scripts/build/bridge-plugins.sh`, установите `neverlauncher-forge-bridge-0.14.7.jar` или `neverlauncher-neoforge-bridge-0.14.7.jar` строго на соответствующую платформу, добавьте `forgeSha256`/`neoforgeSha256` из `BRIDGE_RELEASE_ALLOWLIST.json`, зарегистрируйте canonical kind и enroll public Ed25519 key. Затем проверьте heartbeat и `allow → replay deny → revoke → deny`.

### Upgrade 0.14.5 → 0.14.6

Остановите 0.14.5 API instances, создайте проверенный backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Current migration должна быть `0026_fabric_server_bridge_0146` до запуска 0.14.6 Backend. Migration только расширяет ServerBridge kind constraint и сохраняет существующие node identities/tickets.

Соберите `scripts/build/bridge-plugins.sh`, установите `neverlauncher-fabric-bridge-0.14.6.jar` в `/mods` Fabric 1.21.1 server вместе с Fabric API и добавьте `fabricSha256` из `BRIDGE_RELEASE_ALLOWLIST.json` в production policy. Зарегистрируйте `kind=fabric`, enroll public Ed25519 key и проверьте heartbeat плюс allow → replay deny → revoke → deny. Клиентский NeverLauncher/Fabric мод для этого bridge не требуется.

### Upgrade 0.14.4 → 0.14.5

Остановите 0.14.4 API instances, примените `nl db migrate apply` и убедитесь через `nl db migrate verify`, что current migration — `0025_proxy_family_0145`. Обновите release allowlist точными SHA-256 `velocity/bungeecord/waterfall/bukkit/spigot/paper/purpur/folia`, установите platform-matched proxy JAR и дождитесь signed heartbeat каждого node. BungeeCord/Waterfall используют отдельные node identities; private Ed25519 keys остаются только на соответствующем proxy.


## Запуск

```bash
cp deploy/production/env.production.example deploy/production/.env.production
# замените все значения CHANGE_ME
docker compose --env-file deploy/production/.env.production -f deploy/production/docker-compose.yml build
docker compose --env-file deploy/production/.env.production -f deploy/production/docker-compose.yml up -d
```

Образ Admin собирается из `apps/admin/Dockerfile`; каталог `apps/admin/dist` на host не требуется.

## База данных и первичная инициализация

`NEVERLAUNCHER_DATABASE_AUTO_MIGRATE=true` применяет встроенную цепочку production-миграций под PostgreSQL advisory lock. Если auto-migrate отключён, примените миграции явно через `nl db migrate apply`; API откажется запускаться или переходить в readiness при pending-миграциях либо несовпадении checksum.


### Upgrade 0.14.3 → 0.14.4

Остановите 0.14.3 API instances, создайте проверенный backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Current migration должна быть `0024_bukkit_family_0144` до запуска 0.14.4 Backend. Migration сохраняет существующие Velocity/Paper/Purpur nodes и расширяет допустимый `kind` на Bukkit/Spigot/Folia.

Соберите `scripts/build/bridge-plugins.sh` и установите JAR, соответствующий фактической платформе node: `bukkit`, `spigot`, `paper`, `purpur` или `folia`. Обновите `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` из нового `BRIDGE_RELEASE_ALLOWLIST.json`: для 0.14.4 production policy обязательны отдельные hashes Bukkit/Spigot/Paper/Purpur/Folia и Velocity. Folia node должен использовать Folia JAR с `folia-supported: true`; platform mismatch отключается fail-closed. После rollout проверьте heartbeat и signed allow/revoke/deny login flow каждого типа.

### Upgrade 0.14.2 → 0.14.3

Остановите 0.14.2 API instances, создайте проверенный backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Current migration должна быть `0023_one_time_join_tickets_0143` до запуска 0.14.3 Backend.

Migration намеренно fail-closed инвалидирует оставшиеся active ServerBridge tickets 0.14.2 и очищает ephemeral `minecraft_joins`: старые записи не содержат identity binding/redemption proof и не могут считаться доказанно одноразовыми. После запуска выдайте свежий join и проверьте, что он имеет `ticketVersion=2`, привязан к текущему Ed25519 `identity_epoch/key_fingerprint`, первый signed validate переводит ticket в `consumed`, а replay отклоняется. Для Yggdrasil совместимости первый валидный `/hasJoined` также должен consume-ить authorization, повторный — возвращать отсутствие join.

### Upgrade 0.14.1 → 0.14.2

Остановите 0.14.1 API instances, создайте проверенный backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Current migration должна быть `0022_serverbridge_crypto_node_identities_0142` до запуска 0.14.2 Backend.

Migration fail-closed выводит прежние active ServerBridge nodes из эксплуатации: bearer hashes очищаются, статус становится `identity-enrollment-required`, незавершённые join tickets инвалидируются. Установите bridge plugin 0.14.2 на каждом Velocity/Paper/Purpur node; при первом старте он локально создаст Ed25519 `node-identity.properties` и выведет только public key/fingerprint. Передавайте Backend только public key и выполните административный `POST /api/v1/server-bridge/servers/{serverId}/rotate-identity` с `{"keyAlgorithm":"ed25519","publicKey":"..."}`. Private key не копируется в Backend/env и должен оставаться на node. После enrollment проверьте heartbeat, integrity measurement и signed validate-join.

### Upgrade 0.14.0 → 0.14.1

Остановите 0.14.0 API instances, создайте проверенный backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"`. Current migration должна быть `0021_serverbridge_protocol_v2_0141` до запуска 0.14.1 Backend.

Migration переносит legacy ServerBridge metadata/textures из последнего persisted snapshot, но не может восстановить server credential hash и active join bearer hash, которые 0.14.0 намеренно не сериализовал. Такие nodes помечаются `credential-rotation-required`; после запуска 0.14.1 ротируйте server token административным endpoint и обновите token в конфигурации соответствующего Velocity/Paper/Purpur bridge. Bridge plugin должен быть 0.14.1 и отправлять Protocol v2.

### Upgrade 0.13.9 → 0.13.10

Остановите 0.13.9 API instances, проверьте backup и выполните `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"`, затем `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"` до запуска 0.13.10 Backend. Migration `0020_guard_migration_compatibility_stabilization_01310` намеренно fail-closed отклоняет partial/ambiguous persisted Guard snapshots; не удаляйте constraints и не подменяйте checksum. Исправьте конкретные legacy rows на копии БД, повторите rehearsal `e2e/scripts/run-guard-migration-e2e.sh`, затем повторите production upgrade.

После upgrade `GET /ready` должен подтверждать current migration `0020_guard_migration_compatibility_stabilization_01310`. Для Guard release certification per-platform result обязан быть связан с тем же repository/commit/run, что aggregate matrix.

### Device Trust Release 0.13.0

`0.13.0` не добавляет новую DB migration: перед запуском API `nl db migrate verify` должен подтверждать `0018_device_trust_stabilization_01210`. Для официальной публикации release bundle задайте `NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE`, `NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE` и `NEVERLAUNCHER_SOURCE_COMMIT`; `nl release publish-check` fail-closed проверит обе certification для exact commit. Bundle без public matrices является release candidate, а не publishable Device Trust Release.

### Upgrade 0.12.9 → 0.12.10

Перед обновлением существующей `0.12.9` БД создайте и проверьте backup, затем остановите старые API instance, чтобы они не писали Device Trust state параллельно migration. Примените `nl db migrate apply --dsn "$NEVERLAUNCHER_DATABASE_DSN"` и сразу `nl db migrate verify --dsn "$NEVERLAUNCHER_DATABASE_DSN"` до запуска `0.12.10` API. Migration `0018_device_trust_stabilization_01210` fail-closed остановится при cross-user/структурно противоречивых Device Trust связях; не обходите ошибку ручным удалением constraints — восстановите/исправьте данные из проверенного backup и повторите upgrade.

Для rehearsal на копии production schema используйте `e2e/scripts/run-device-trust-migration-e2e.sh`: release CI строит exact `0.12.9` schema (`0001..0017`) и требует подтверждённый переход на `0018`.

Для новой установки:

1. Задайте сильный одноразовый `NEVERLAUNCHER_BOOTSTRAP_TOKEN`.
2. Запустите стек.
3. Вызовите `POST /api/v1/install/bootstrap-admin` с `X-NeverLauncher-Bootstrap-Token`.
4. Авторизуйтесь и создайте первый проект через `POST /api/v1/install/first-project`.
5. После установки `installation_completed` удалите bootstrap token из окружения deployment.

## Redis rate limiting

Compose формирует `NEVERLAUNCHER_REDIS_URL` из `REDIS_PASSWORD`. Production rate limiting распределённый и fail-closed: отказ Redis приводит к ошибке запуска/readiness вместо скрытого перехода на per-process limiter. Redis не публикуется на host.

## Доверенные proxy

Compose-сеть использует фиксированный внутренний CIDR. Заголовки `X-Forwarded-For` и `X-Real-IP` принимаются только от явно доверенных proxy. Заголовки от недоверенных узлов игнорируются. Не задавайте публичную Internet-сеть в `NEVERLAUNCHER_TRUSTED_PROXY_CIDRS`.

## TLS

Встроенный ingress использует только HTTP и рассчитан на работу за реальным TLS endpoint. Публичное развёртывание обязано использовать HTTPS и `NEVERLAUNCHER_PUBLIC_URL=https://...`. Настройки TLS 1.2/1.3, HSTS и proxy headers описаны в [`TLS.md`](./TLS.md).

## Хранилище

Перед стартом API одноразовый `api-volume-init` выставляет UID/GID `10001:10001` для named volumes storage/backups; сам API остаётся непривилегированным пользователем `neverlauncher`. Это работает и для уже существующих root-owned volumes.

Local storage монтируется в `/var/lib/neverlauncher/storage`, а backup — отдельно в `/var/lib/neverlauncher/backups`. S3-compatible драйвер записывает входящий поток во временный файл с ограниченным размером, параллельно вычисляет SHA-256 и затем отправляет файл в S3. Ошибка инициализации или health-check S3 останавливает API; fallback на local storage отсутствует.

## CORS и backup

Задайте `NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` явным списком HTTPS origin. Wildcard `*` в production отклоняется при старте. `NEVERLAUNCHER_BACKUP_ROOT` обязан быть отделён от local storage. Backup включает PostgreSQL dump и фактические storage-объекты; destructive restore требует точного подтверждения backup ID.

## Проверка состояния

```bash
curl -fsS http://127.0.0.1/health
curl -fsS http://127.0.0.1/ready
```

`/ready` включает совместимость миграций PostgreSQL и состояние Redis limiter.

## Релизные проверки

```bash
python3 scripts/contracts/validate-openapi.py
export NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE=/secure/release-private.pem
export NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE=/etc/neverlauncher/release-public.pem
bash scripts/release/build-release.sh
NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh
```

`.github/workflows/ci.yml` — обязательный CI: repository policy, Go race/vet/build, Admin/Desktop, Rust fmt/clippy/test/build, Tauri, реальные ServerBridge, production-контейнеры и PostgreSQL/Redis/Velocity/Spigot/Paper/Purpur/Folia/Fabric/Forge/NeoForge E2E должны пройти успешно.

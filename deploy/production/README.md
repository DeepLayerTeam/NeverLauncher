# Production-развёртывание NeverLauncher 0.10.3

Production-стек использует PostgreSQL, Redis с паролем, Backend API, неизменяемый образ Admin и Nginx ingress. Проверка совместимости БД, доверие к манифестам и распределённый rate limiting работают fail-closed.

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

`.github/workflows/ci.yml` — обязательный CI: repository policy, Go race/vet/build, Admin/Desktop, Rust fmt/clippy/test/build, Tauri, реальные ServerBridge, production-контейнеры и PostgreSQL/Redis/Velocity/Paper/Purpur E2E должны пройти успешно.

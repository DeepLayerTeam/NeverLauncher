# NeverLauncher Backend API 0.10.4

Backend предоставляет один production-контракт: `/api/v1`. Исторические маршрутизаторы `/api/v2`–`/api/v5` не регистрируются.

## Публичные маршруты и установка

```text
GET  /health
GET  /ready
GET  /metrics
GET  /api/v1/status
GET  /api/v1/runtime/requirements
GET  /api/v1/loaders
GET  /api/v1/install/wizard
GET  /api/v1/install/profiles
GET  /api/v1/install/readiness
POST /api/v1/install/bootstrap-admin
POST /api/v1/install/first-project
```

## Авторизация и администрирование

Канонический API реализует login/refresh/logout, отзыв сессий, роли, password/TOTP/recovery-сценарии, CRUD проектов/профилей/каналов, пользователей, аудит, проверку хранилища, публикацию версий и операции с пакетами в `/api/v1/auth/*` и `/api/v1/admin/*`.

## Пакеты и манифесты

Создание пакета, загрузка файлов, валидация, подпись, staging, smoke-test, публикация и rollback канала доступны через `/api/v1/packages/*` и `/api/v1/channels/*`. Опубликованные манифесты подписываются Ed25519 и проверяются NeverRuntime по закреплённому public key.

## ServerBridge

Velocity/Paper/Purpur используют `/api/v1/server-bridge/*`, `/api/v1/session/*` и `/api/v1/textures/*` для регистрации, heartbeat, проверки входа, инвалидирования сессий и получения текстур.

## Операции

Диагностика, реальный PostgreSQL/storage backup, проверочный restore dry-run, подтверждаемый restore, audit export, diagnostic bundle и compliance доступны через `/api/v1/operations/*`. `/ready` работает fail-closed при несовместимых миграциях PostgreSQL и при недоступном Redis rate limiter в production fail-closed режиме.

## Контракт

Канонический контракт хранится в:

```text
schemas/openapi.yaml
```

Перегенерация и проверка по фактическому router:

```bash
python3 scripts/contracts/generate_openapi.py
python3 scripts/contracts/validate-openapi.py
```

## Тесты

Канонические HTTP integration tests находятся в `services/api/internal/httpapi/*_test.go` и напрямую проверяют `/api/v1`, включая auth, CRUD, публикацию пакетов, security hardening, backup и ServerBridge. Исторические `/api/v2`–`/api/v5` проверяются как отсутствующие.

```bash
go test ./...
go test -race ./...
go vet ./...
go build -trimpath ./cmd/neverlauncher-api
```

Для offline-окружения без pgx в локальном module cache:

```bash
go test -tags neverlauncher_nopgx ./...
go vet -tags neverlauncher_nopgx ./...
```

Production CI всегда собирает обычный pgx-бинарник; `neverlauncher_nopgx` не является fallback для production-релиза.

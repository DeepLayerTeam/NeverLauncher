# Локальная разработка

## Структура monorepo

Проект — несколько самостоятельных Go и Cargo-пакетов, React-приложения и Gradle-модули. **В корне нет общего `go.mod` или `package.json`**, поэтому команды выполняются из каталогов модулей.

| Задача | Команда из корня |
| --- | --- |
| Проверить единую версию | `python3 scripts/version/manage.py check` |
| Проверить OpenAPI | `python3 scripts/contracts/validate-openapi.py` |
| Go API | `(cd services/api && go test ./...)` |
| Go CLI | `(cd cli && go test ./...)` |
| Admin UI | `(cd apps/admin && npm ci && npm run build)` |
| Desktop UI | `(cd apps/desktop && npm ci && npm run build)` |
| Runtime | `(cd runtime/runtime && cargo test)` |
| Compatibility target manifest | `python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json` |

## Запуск UI

```bash
cd apps/admin
npm ci
npm run dev
```

Для Desktop UI используются аналогичные `npm ci`/`npm run dev` в `apps/desktop`, однако интеграционные Tauri APIs требуют нативный Tauri context. Наличие веб-сервера Vite не гарантирует работу системного keyring и запуска Minecraft.

## Backend

Переменные ориентировочного dev окружения хранятся в `.env.example`. Конфигурация зависит от PostgreSQL, Redis и storage driver; подробнее в [reference/configuration.md](../reference/configuration.md). Не смешивайте development и production окружения.

## Тесты и CI

Тесты по компонентам можно запускать отдельно, но полный gate выполняется в `.github/workflows/ci.yml`; локальный `scripts/release/preflight.sh` требует дополнительных зависимостей. Проверки macOS/Windows и реальных клиентов Minecraft проводятся в соответствующих runner. Для ошибок CI см. [../troubleshooting/ci.md](../troubleshooting/ci.md).

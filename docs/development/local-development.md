# Локальная разработка

## Структура монорепозитория

Проект состоит из нескольких самостоятельных модулей Go и Cargo, приложений React и модулей Gradle. **В корне нет общего `go.mod` или `package.json`**, поэтому команды выполняются из каталогов соответствующих модулей.

| Задача | Команда из корня |
| --- | --- |
| Проверить согласованность версий | `python3 scripts/version/manage.py check` |
| Проверить контракт OpenAPI | `python3 scripts/contracts/validate-openapi.py` |
| Go API | `(cd services/api && go test ./...)` |
| Go CLI | `(cd cli && go test ./...)` |
| Административный интерфейс | `(cd apps/admin && npm ci && npm run build)` |
| Интерфейс Desktop | `(cd apps/desktop && npm ci && npm run build)` |
| Среда выполнения | `(cd runtime/runtime && cargo test)` |
| Проверить целевые конфигурации совместимости | `python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json` |

## Запуск интерфейса

```bash
cd apps/admin
npm ci
npm run dev
```

Для интерфейса Desktop аналогичные команды `npm ci` и `npm run dev` выполняются в `apps/desktop`. Однако интеграционные API Tauri требуют нативного контекста Tauri. Запущенный сервер Vite сам по себе не гарантирует работу системного хранилища ключей и запуска Minecraft.

## Бэкенд

Примеры переменных локального окружения находятся в `.env.example`. Настройки зависят от PostgreSQL, Redis и выбранного драйвера хранилища; подробности — в [справочнике конфигурации](../reference/configuration.md). Не смешивайте окружения разработки и промышленной эксплуатации.

## Тесты и непрерывная интеграция

Тесты каждого компонента можно запускать отдельно, но полный набор обязательных проверок определяется `.github/workflows/ci.yml`. Локальный сценарий `scripts/release/preflight.sh` требует дополнительных зависимостей. Проверки macOS/Windows и реальных клиентов Minecraft выполняются на соответствующих тестовых исполнителях. При ошибках CI см. [диагностику CI](../troubleshooting/ci.md).

# Быстрый старт

## 1. Проверьте дерево

```bash
cat VERSION
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
```

Для полной разработки потребуются Go, Python 3, Node.js/npm, Rust/Cargo и Java/Gradle; конкретные требования по каждому модулю — [DEVELOPMENT.md](../../DEVELOPMENT.md). У проекта нет единой команды, собирающей все платформы без дополнительных toolchains.

## 2. Соберите компоненты

```bash
(cd services/api && go test ./... && go build ./...)
(cd cli && go test ./... && go build ./...)
(cd apps/admin && npm ci && npm run build)
(cd apps/desktop && npm ci && npm run build)
(cd runtime/neverruntime && cargo test)
```

Выходные файлы от этих команд не означают готовую подписанную Desktop-поставку. Сборка, нотариализация, доставка JRE и проверка Guard выполняются отдельными release workflow.

## 3. Конфигурируйте окружение

`.env.example` — перечень параметров локальной разработки; `deploy/production/env.production.example` — шаблон production. Заполняйте их **у себя** и храните секреты вне Git. Сам факт существования `.env` не означает автоматическую загрузку переменных Go-исполняемым файлом.

## 4. Дальше

- Запуск продакшна: [production.md](production.md).
- Профили и клиенты: [../clients/profiles-and-launch.md](../clients/profiles-and-launch.md).
- URL и методы: [../reference/api.md](../reference/api.md).
- Ошибки и диагностика: [../troubleshooting/common.md](../troubleshooting/common.md).

# Разработка Launcher

## Требования

- Go 1.23.x — версия runner в основном CI (модули указывают минимум Go 1.22).
- Python 3 для контрактов, верификации и матриц.
- Node.js/npm, TypeScript и Vite для `apps/admin` и `apps/desktop` (ориентируйтесь на lockfiles).
- Rust/Cargo и системные зависимости Tauri для Desktop/Runtime/Guard.
- JDK, Gradle и Gradle-plugin toolchains для серверных Java-мостов; корневой Gradle wrapper в текущем архиве отсутствует.
- Docker Compose/PostgreSQL/Redis — для интеграционных сценариев.

## Команды, подтверждённые репозиторием

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/device_trust/matrix.py validate --targets device-trust/targets.json
python3 scripts/guard_ci/matrix.py validate --targets guard-ci/targets.json
(cd services/api && go test ./... && go build ./...)
(cd cli && go test ./... && go build ./...)
(cd apps/admin && npm ci && npm run build)
(cd apps/desktop && npm ci && npm run build)
(cd runtime/runtime && cargo test)
```

Отдельный native build: `cd apps/desktop/src-tauri && cargo build` (не равен сборке установочного пакета). Проверки разных платформ могут требовать оборудования, подписывающих ключей и upstream-загрузок.

## Backend и настройка

Для локальной среды изучите `.env.example`. Запускайте PostgreSQL/Redis отдельно и передавайте переменные сервису из защищённого окружения; Go-приложение **не обязано автоматически читать `.env` как shell-файл**. Никакие примеры `change-me-*` нельзя использовать за пределами локальной среды. Схема HTTP-операций: `schemas/openapi.yaml`.

## Качество изменений

1. Делайте узкий PR с проверяемым результатом и тестами.
2. Изменения API сопровождайте обновлением canonical OpenAPI и регрессионными тестами.
3. Перед PR проверяйте `scripts/version/manage.py check`, `scripts/contracts/validate-openapi.py`, релевантные Go/Rust/TypeScript-тесты и offline gates.
4. Не утверждайте успешность всей кроссплатформенной матрицы по локальному Linux-тесту.
5. Для выпуска следуйте `scripts/release/preflight.sh`; `NEVERLAUNCHER_PREFLIGHT_STRICT=1` может требовать credentials, реального upstream и CI evidence.

См. [развёрнутое руководство](docs/development/local-development.md), [соглашения о PR](CONTRIBUTING.md), [диагностику CI](docs/troubleshooting/ci.md).

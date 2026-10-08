# Smoke-контроли NeverLauncher

Текущий smoke-контур проверяет только рабочие production-пути; исторические RC/Stable метаданные-контроли и fake Minecraft demo-kit не используются.

- `offline/` — репозиторий политика, CLI/API тесты, сборка, выравнивание версии, OpenAPI, Матрица совместимости definition/aggregator усиление защиты, синтаксис release-скриптов и ServerBridge сборка при доступных Gradle/JDK.
- `api-required/` — канонические `/health`, `/ready`, `/api/v1/status` и проекты.
- `docker-required/` — проверка рабочий Compose.
- `frontend/` — Admin/Desktop web и Tauri проверяет.
- `release-required/` — проверка собранного комплект релиза.

Полный реальный клиент сценарий находится в `e2e/scripts/run-minecraft-e2e.sh`. Основной CI выполняет полный Vanilla + Velocity/Spigot/Paper/Purpur/Folia рабочий E2E, а `.github/workflows/compatibility.yml` использует тот же среда выполнения путь для публичной Vanilla/Fabric/Quilt/Forge/NeoForge матрицы.

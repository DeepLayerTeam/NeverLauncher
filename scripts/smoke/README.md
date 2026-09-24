# Smoke-gates NeverLauncher

Текущий smoke-контур проверяет только рабочие production-пути; исторические RC/Stable metadata-gates и fake Minecraft demo-kit не используются.

- `offline/` — repository policy, CLI/API tests, сборка, выравнивание версии, OpenAPI, Compatibility Matrix definition/aggregator hardening, синтаксис release-скриптов и ServerBridge build при доступных Gradle/JDK.
- `api-required/` — канонические `/health`, `/ready`, `/api/v1/status` и проекты.
- `docker-required/` — проверка production Compose.
- `frontend/` — Admin/Desktop web и Tauri checks.
- `release-required/` — проверка собранного release bundle.

Полный actual-client сценарий находится в `e2e/scripts/run-minecraft-e2e.sh`. Основной CI выполняет полный Vanilla + Velocity/Spigot/Paper/Purpur/Folia production E2E, а `.github/workflows/compatibility.yml` использует тот же runtime path для публичной Vanilla/Fabric/Quilt/Forge/NeoForge матрицы.

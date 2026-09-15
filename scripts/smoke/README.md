# Smoke-gates NeverLauncher 0.10.0-P3.2v4

Актуальный P3.2v3 smoke-контур проверяет только рабочие production-пути. Исторические RC/Stable metadata-gates и fake Minecraft demo-kit удалены из preflight.

- `offline/` — repository policy, CLI/API tests, сборка, выравнивание версии, OpenAPI, синтаксис release-скриптов и ServerBridge build при доступных Gradle/JDK.
- `api-required/` — канонические `/health`, `/ready`, `/api/v1/status` и проекты.
- `docker-required/` — проверка production Compose.
- `frontend/` — Admin/Desktop web и Tauri checks.
- `release-required/` — проверка собранного release bundle.

Полный сценарий Velocity/Paper/Purpur находится в `e2e/scripts/run-minecraft-e2e.sh` и выполняется обязательной GitHub CI-задачей.

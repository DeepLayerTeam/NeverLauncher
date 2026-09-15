# Production E2E NeverLauncher 0.10.7

Основной production E2E запускается командой:

```bash
e2e/scripts/run-minecraft-e2e.sh
```

`0.10.7` использует настоящий Minecraft Java Client, а не Java fixture. Один и тот же script поддерживает два режима.

### Полный production mode

По умолчанию `NEVERLAUNCHER_E2E_MODE=full`: поднимаются PostgreSQL/Redis, production-configured API, Velocity 3.4.0, Paper 1.21.1 и Purpur 1.21.1. Vanilla 1.21.1 проходит materialization, локальную SHA-256 проверку, upload через `/api/v1`, Ed25519 publish, clean NeverRuntime sync, реальный запуск под Xvfb и фактический вход на Paper. После revoke проверяется deny; Velocity/Purpur дополнительно проходят protocol-level allow/revoke/deny.

### Compatibility mode

Публичная матрица вызывает `e2e/scripts/run-compatibility-case.sh`. Wrapper переводит основной script в `NEVERLAUNCHER_E2E_MODE=compatibility`, запускает только обязательный Paper node и выбирает loader через переменные:

```text
NEVERLAUNCHER_E2E_MINECRAFT_VERSION
NEVERLAUNCHER_E2E_LOADER=vanilla|fabric|quilt|forge|neoforge
NEVERLAUNCHER_E2E_LOADER_VERSION=<selector>
NEVERLAUNCHER_COMPAT_TARGET_ID=<canonical target id>
```

Для Fabric/Quilt/Forge/NeoForge используется соответствующий рабочий `nl runtime <loader>-package`; mutable selector разрешается materializer-ом до concrete loader version. После формирования package все loader families проходят одинаковую trust boundary:

```text
materialize
 -> nl client verify
 -> canonical API upload
 -> immutable Ed25519 publish
 -> pinned NeverRuntime verify
 -> clean SHA-256 sync
 -> Xvfb actual Minecraft launch
 -> --quickPlayMultiplayer 127.0.0.1:25571
 -> real Paper world join
 -> session revoke
 -> subsequent join denied
```

`run-compatibility-case.sh` формирует `e2e/compatibility-result/compatibility-result.json`. PASS выставляется только если присутствуют package verification, valid manifest signature, clean sync, actual-client launch, Paper join, revoke/deny и healthy Paper evidence. Результат содержит exact Git commit и GitHub Actions run ID; агрегатор не принимает result от другого запуска.

`e2e/scripts/publish-client-package.py` повторно SHA-256-хеширует каждый materialized artifact перед multipart upload, сверяет checksum/size из Backend и отклоняет path traversal и symlink-компоненты внутри client tree.

Канонический Compose-файл: `e2e/docker-compose.minecraft-e2e.yml`. Runtime/evidence создаются в `e2e/runtime/` и `e2e/compatibility-result/`, оба каталога исключены из source tree.

Для локального запуска нужны Docker, Go, Rust/Cargo, JDK 21, Gradle, `curl`, `jq`, Python 3, `xvfb-run` и системные OpenGL/X11 библиотеки. Нужен сетевой доступ к Mojang, Fabric/Quilt Meta, Forge/NeoForge Maven и registry/репозиториям build pipeline.

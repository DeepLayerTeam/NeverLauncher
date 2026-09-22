# Production E2E NeverLauncher

## Device Trust PostgreSQL E2E (`0.12.9`)

Полный Device Trust lifecycle запускается отдельно от Minecraft actual-client E2E:

```bash
bash e2e/scripts/run-device-trust-e2e.sh
```

Сценарий поднимает production-configured Backend, PostgreSQL и Redis через `docker-compose.federation-e2e.yml`, явно применяет и проверяет migrations и выполняет реальные Ed25519/P-256 signatures. Проверяются registration replay deny, `binding_epoch`, signed refresh, dual-proof rotation, tombstone старого fingerprint, ServerBridge deny после replacement, persisted risk step-up, challenge-response attestation + replay deny, deny recovery без phishing-resistant step-up, реальная WebAuthn P-256 registration/assertion ceremony, успешный key recovery и revoke cascade.

Публикуемые evidence находятся только в `e2e/device-trust-result/`. Private keys и runtime credentials живут в `e2e/device-trust-runtime/` и не являются evidence; перед PASS script fail-closed проверяет publishable directory на access/refresh/private-key material. Public matrix собирается `.github/workflows/device-trust.yml` только из exact-commit/run results.

Для локального protocol E2E нужны Docker/Compose, Go, `psql`, `curl`, `jq`, Python 3 и OpenSSL. Strict release preflight включает этот сценарий автоматически; вручную: `NEVERLAUNCHER_PREFLIGHT_DEVICE_TRUST_E2E=1 ./scripts/release/preflight.sh`.

Основной production E2E запускается командой:

```bash
e2e/scripts/run-minecraft-e2e.sh
```

Production E2E использует настоящий Minecraft Java Client, а не Java fixture. Один и тот же script поддерживает два режима.

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
## Federation/PostgreSQL Auth Federation E2E (`0.12.0`)

Для auth/federation release gate используется отдельный сценарий:

```bash
bash e2e/scripts/run-federation-postgres-e2e.sh
```

Он поднимает PostgreSQL, Redis и три Backend instance (`api-a`, `api-b`, `api-c`), применяет и проверяет migration catalog, выполняет login на A, перезапускает A, делает refresh через разные instances, воспроизводит старый refresh token и требует, чтобы compromise/revoke был виден всем трём Backend. Сценарий требует Docker/Compose, `psql`, `curl`, `jq`, Go и Python.

Быстрый connector/failure gate без Docker:

```bash
python3 scripts/test/federation-e2e.py
```

Strict release preflight включает PostgreSQL сценарий автоматически; вручную это можно включить через `NEVERLAUNCHER_PREFLIGHT_FEDERATION_POSTGRES=1`.


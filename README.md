# NeverLauncher

[![Основной CI](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/ci.yml)
[![Матрица совместимости](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/compatibility.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/compatibility.yml)

NeverLauncher — self-hosted LauncherOps-платформа для Minecraft-проектов. Текущий релиз — **Minecraft Compatibility Release**: Compatibility Engine, Managed Java, Vanilla/Fabric/Quilt/Forge/NeoForge materialization, настоящий Minecraft Client E2E и публичная CI Compatibility Matrix сведены в один release-grade контур.

Главное изменение Minecraft Compatibility Release относительно `0.10.7` — compatibility evidence теперь связано с самим production release: официальный `release publish-check` требует machine-verifiable матрицу для той же версии/commit, проверяет все required targets и включает matrix/targets/certification в общий `SHA256SUMS`, Ed25519 signature и provenance boundary. Bundle без такого evidence можно собрать как CI candidate, но нельзя подтвердить как Minecraft Compatibility Release.

## Рабочий контур

```text
Mojang metadata -> проверенное Vanilla tree
Forge/NeoForge Maven -> installer.jar + SHA-1
                     -> install_profile.json/version.json
                     -> embedded Maven + verified dependencies
                     -> client processors + output verification
                     -> normalized child version profile
                     -> SHA-256 Never package -> signed immutable release
                     -> Compatibility Engine -> Managed Java -> JVM
```

Сохраняется processor-based Forge/NeoForge pipeline, введённый в `0.10.4`, и стабилизационный hardening `0.10.7`: exclusive materialization lock, bounded upstream retry, symlink-safe client tree, deterministic natives/processors state и строгий CI evidence.

## Minecraft Compatibility Release

- exclusive materialization lock на каждый `clientDir` для Vanilla/Fabric/Quilt/Forge/NeoForge;
- retry transient HTTP `408/425/429/5xx` и bounded `Retry-After`;
- запрет symlink-компонентов внутри materialized client tree и symlink artifacts при package build;
- portable atomic replacement повреждённых файлов;
- очистка и полная пересборка generated natives перед упаковкой;
- очистка Forge/NeoForge installer scratch data перед processors;
- Compatibility Engine повторно проверяет отсутствие symlink path components непосредственно перед runtime resolution;
- CI aggregator требует `exitCode=0`, healthy Paper, полный evidence set и loader identity, а не только поле `status=passed`.

Эти проверки находятся в исполняемом коде и regression tests; repository policy дополнительно запрещает выпуск при удалении обязательных compatibility primitives.

### Release-bound compatibility certification

Официальный publish flow использует агрегированный `matrix.json` из `.github/workflows/compatibility.yml` и создаёт в release bundle три обязательных файла:

```text
COMPATIBILITY_TARGETS.json
COMPATIBILITY_MATRIX.json
COMPATIBILITY_CERTIFICATION.json
```

Certification повторно проверяет product version, exact source commit, run ID, полный набор required targets, immutable resolved loader versions, `exitCode=0`, actual-client/package/signature/sync/Paper/revoke evidence и SHA-256 каждого per-target evidence JSON. Все три файла входят в `SHA256SUMS` и поэтому защищены общей Ed25519 release signature.

Сборка сертифицированного bundle:

```bash
export NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE=/path/to/matrix.json
export NEVERLAUNCHER_SOURCE_COMMIT=$(git rev-parse HEAD)
bash scripts/release/build-release.sh
```

Финальная проверка перед публикацией:

```bash
VERSION="$(cat VERSION)"
nl release publish-check "dist/release-${VERSION}" --public-key /secure/release-public.pem
```

## Managed Java

NeverRuntime выбирает JVM требуемой major-версии из signed manifest/Mojang metadata и при необходимости устанавливает проверенный Temurin runtime. Поддерживаются Java 8, 17, 21 и 25. Forge/NeoForge processor pipeline принимает `--java` или `NEVERLAUNCHER_JAVA`; если путь не задан, используется подходящая системная Java. Версия installer JVM проверяется до запуска processors.

```bash
neverruntime java ensure --major 21 --distribution temurin
```

## Vanilla / Fabric / Quilt

Сохраняется materialization-контур `0.10.2`–`0.10.3`: Mojang client/libraries/assets/natives/logging проверяются по upstream SHA-1/size и затем фиксируются SHA-256 в Never release; Fabric и Quilt получают concrete loader profile через официальные Meta API и materialize Maven dependencies до публикации immutable release.

```bash
nl runtime vanilla-package --minecraft 1.21.1 --client-dir .neverlauncher/vanilla/1.21.1 --output client-package.json
nl runtime fabric-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/fabric/1.21.1 --output client-package.json
nl runtime quilt-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/quilt/1.21.1 --output client-package.json
```

## Forge + NeoForge

Новые materializer-команды:

```bash
nl runtime forge-install \
  --minecraft 1.20.1 \
  --loader-version latest-stable \
  --client-dir .neverlauncher/forge/1.20.1

nl runtime forge-package \
  --minecraft 1.20.1 \
  --loader-version 47.4.0 \
  --client-dir .neverlauncher/forge/1.20.1 \
  --project my-project \
  --profile forge \
  --channel stable \
  --output client-package.json

nl runtime neoforge-package \
  --minecraft 1.21.1 \
  --loader-version latest-stable \
  --client-dir .neverlauncher/neoforge/1.21.1 \
  --project my-project \
  --profile neoforge \
  --channel stable \
  --output client-package.json
```

Production pipeline выполняет:

1. разрешение Minecraft и materialization Vanilla base;
2. выбор конкретной Forge/NeoForge версии через Maven metadata либо явный `--loader-version`;
3. загрузку официального `installer.jar` только по HTTPS и проверку upstream `.sha1`;
4. чтение `install_profile.json` и встроенного `version.json` непосредственно из installer JAR;
5. безопасное извлечение встроенного `maven/` и installer `data/` без path traversal/symlink;
6. materialization installer libraries и processor classpath;
7. выполнение только client processors через Java, с `Main-Class` из JAR manifest, timeout и прямой передачей аргументов без shell;
8. разрешение Forge/NeoForge installer tokens `{ROOT}`, `{MINECRAFT_JAR}`, `{INSTALLER}`, `{LIBRARY_DIR}`, `{SIDE}`, `{DATA}` и Maven references `[group:artifact:version...]`;
9. проверку processor outputs по SHA-1/SHA-256 и пропуск уже корректно созданных outputs при повторной установке;
10. materialization runtime libraries из child `version.json`, включая локально сгенерированные processor artifacts;
11. запись нормализованного `versions/<id>/<id>.json` и стандартную упаковку в SHA-256 Never package.

Для тестов/зеркал доступны `--installer-url`, `--installer-sha1` и `--maven-metadata-url`. В strict mode отсутствие корректного checksum завершает materialization ошибкой.

Текущий compatibility release поддерживает processor-based Forge installers поколения 1.13+ и NeoForge installer format. Legacy Forge до 1.13 намеренно не объявляется готовым и остаётся отдельной задачей compatibility hardening.

## Compatibility Engine

При `runtime.launch.classpathStrategy = "compatibility"` NeverRuntime читает подписанный child `version.json`, разрешает `inheritsFrom`, Mojang rules, ordered classpath, native classifiers, JVM/game arguments и logging config. Forge/NeoForge child profile поэтому запускается тем же runtime path, что Vanilla/Fabric/Quilt, без отдельного launch fallback.

Каждый metadata/classpath/native/logging path, использованный engine, обязан входить в подписанный manifest. Installer JAR и промежуточные installer data хранятся в `.neverlauncher/` и в клиентский package не попадают; только нормализованные runtime artifacts становятся частью immutable release.

Прямое разрешение установленного дерева:

```bash
neverruntime compatibility --root .neverlauncher/client --version <profile-id>
```

## Компоненты

- **Backend API** — единый `/api/v1`, миграции PostgreSQL, подписанные манифесты, авторизация и серверные сессии, Redis rate limiting, доверенные proxy, local/S3-хранилище, резервное копирование, диагностика и ServerBridge.
- **CLI `nl`** — рабочие сценарии установки, авторизации, администрирования, операций, пакетов, релизов и runtime через `/api/v1`; исторические status-only семейства команд удалены.
- **NeverRuntime** — Rust runtime/CLI для Ed25519-проверки, потоковой загрузки и SHA-256, восстановления клиента, определения Java, построения плана запуска и запуска процесса.
- **Desktop** — Tauri-адаптер поверх NeverRuntime с системным защищённым хранилищем учётных данных и контролируемыми JVM-процессами.
- **Admin** — Vite-приложение в неизменяемом production-образе Nginx с CSP.
- **ServerBridge** — реальные плагины Velocity/Paper/Purpur, собираемые против API соответствующих платформ.
- **Развёртывание** — PostgreSQL, Redis с паролем, Backend, Admin и Nginx с fail-closed rate limiting и явным списком доверенных proxy CIDR.

## Канонический API

В production регистрируется только `/api/v1`. Исторические маршрутизаторы `/api/v2`–`/api/v5` отсутствуют намеренно. Канонический контракт хранится в:

```text
schemas/openapi.yaml
```

Перегенерация и проверка контракта по фактическому Go-router:

```bash
python3 scripts/contracts/generate_openapi.py
python3 scripts/contracts/validate-openapi.py
```

Проверка завершается ошибкой, если набор операций router и OpenAPI расходится.

## Локальная проверка

```bash
./scripts/release/preflight.sh
```

Локальный preflight выполняет доступный контур и явно не объявляет его production-ready при пропусках. Для релиза используйте строгий режим, который требует все обязательные проверки:

```bash
NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh
```

Для диагностического локального прогона frontend и Tauri можно включить отдельно:

```bash
NEVERLAUNCHER_PREFLIGHT_FRONTEND=1 ./scripts/release/preflight.sh
NEVERLAUNCHER_PREFLIGHT_TAURI=1 ./scripts/release/preflight.sh
```

## Публичная CI Compatibility Matrix

Канонические цели хранятся в `compatibility/targets.json`; в них нет ручных PASS/FAIL. Workflow `.github/workflows/compatibility.yml` строит dynamic matrix и запускает настоящий клиент для каждого target. Текущая обязательная матрица проверяет Linux x86_64 для Vanilla/Fabric/Quilt/Forge/NeoForge на Minecraft 1.21.1. Mutable loader selector `latest-stable` разрешается в конкретную версию до публикации и не может попасть в PASS-результат как итоговая loader version.

Каждый case генерирует `compatibility-result.json` только после прохождения обязательных evidence-checks: локальная проверка package, Ed25519-подпись immutable manifest, clean sync, запуск настоящего клиента, вход на Paper и fail-closed deny после revoke. Агрегатор `scripts/compatibility/matrix.py` проверяет exact target, commit, Actions run ID, concrete loader version и completeness evidence; missing/duplicate/invalid result делает матрицу failed. Итоговые `matrix.json` и `matrix.md` публикуются в Actions Summary и как artifact.

Локальная проверка definition/aggregator:

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

Подробности: `compatibility/README.md`.

## Настоящий Minecraft Client E2E

Блокирующий production release gate по умолчанию проверяет Vanilla, а compatibility workflow использует тот же production-путь для всех пяти loader families. Java fixture не используется как доказательство совместимости клиента:

```text
официальный Mojang version manifest
 -> Minecraft 1.21.1 client/libraries/assets/natives/logging
 -> полный локальный SHA-256 verify
 -> upload через canonical /api/v1
 -> Ed25519 signed immutable release
 -> чистый NeverRuntime sync из Backend
 -> pinned signature + SHA-256 verify
 -> Xvfb + software OpenGL
 -> настоящий Minecraft Java Client
 -> --quickPlayMultiplayer 127.0.0.1:25571
 -> настоящий Paper 1.21.1
 -> NeverLauncher ServerBridge allow
 -> E2EPlayer joined the game
 -> revoke session -> subsequent join denied
```

Для CI добавлен безопасный `--max-runtime-seconds`: NeverRuntime сам завершает долговременно работающий game process после сбора E2E evidence и отражает это как `timedOut`, не оставляя Java-процесс после job.

Velocity/Purpur продолжают проходить быстрый protocol-level allow/revoke/deny тест, но такой probe больше не считается доказательством Minecraft Client compatibility.

Запуск в окружении с Docker, Gradle, JDK 21, Rust/Cargo, Go, PostgreSQL client, `curl`, `jq`, Python 3, Xvfb и OpenGL/X11 runtime:

```bash
bash e2e/scripts/run-minecraft-e2e.sh
```

## Minecraft Auth Compatibility 2.0

С `0.11.10` federation/migration stability является исполняемым release gate. `python3 scripts/test/federation-e2e.py` прогоняет Local/SQL/HTTP/OIDC/Microsoft/passkey через canonical session и Minecraft compatibility flow, а `bash e2e/scripts/run-federation-postgres-e2e.sh` проверяет restart и multi-instance refresh/revoke/replay на PostgreSQL. Перед production upgrade используйте `nl db migrate apply`, затем `nl db migrate verify`; verify fail-closed отклоняет unknown/future migrations, незапечатанные checksum и checksum drift.

С `0.11.9` login identity и Minecraft identity разделены. Local/SQL/HTTP/OIDC/Microsoft/passkey приводят к одному canonical Never user; из действующей Never session Desktop получает отдельную Minecraft session через `/api/v1/minecraft/session`. Игровой access token opaque и server-side хранится только в виде hash, а стабильный Minecraft UUID строится из immutable Never user ID, а не email.

NeverRuntime передаёт полученные UUID/token в реальный Minecraft launch. Если подписанный release manifest содержит `authlib-injector*.jar`, runtime подключает его как `-javaagent` к Backend, где доступны Yggdrasil-compatible `/authserver/*` и `/sessionserver/session/minecraft/*`. Revoke/logout родительской Never session сразу делает Minecraft token непригодным для validate/join/hasJoined. ServerBridge остаётся отдельным дополнительным контуром доступа к защищённым проектным серверам.

## Production-развёртывание

Основные файлы:

```text
deploy/production/docker-compose.yml
deploy/production/env.production.example
deploy/production/TLS.md
deploy/production/README.md
```

## CI

`.github/workflows/ci.yml` — обязательный CI candidate-контур: policy/contracts, Go, Admin/Desktop, NeverRuntime/Tauri, ServerBridge, production-контейнеры, release candidate bundle и PostgreSQL + Redis + actual Minecraft E2E. `.github/workflows/compatibility.yml` отдельно запускает все пять loader targets и публикует machine-verifiable matrix. Официальная публикация Minecraft Compatibility Release и новее выполняется только после передачи этой matrix в release build и успешного `release publish-check`; обычный candidate bundle сам по себе не считается Minecraft Compatibility Release.

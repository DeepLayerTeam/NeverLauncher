# NeverLauncher

[![Основной CI](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/ci.yml)
[![Матрица совместимости](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/compatibility.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/compatibility.yml)
[![Device Trust Matrix](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/device-trust.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/device-trust.yml)

NeverLauncher — self-hosted LauncherOps-платформа для Minecraft-проектов. Текущий релиз — **Forge + NeoForge Server Bridge / 0.14.7**: ServerBridge Protocol v2 теперь имеет отдельные server-only Forge и NeoForge 1.21.1 модули с Ed25519 node identity, PostgreSQL source of truth, release-hash integrity и one-time join tickets; клиентский bridge-мод для допуска игрока не требуется.

Главное изменение Minecraft Compatibility Release относительно `0.10.7` — compatibility evidence теперь связано с самим production release: официальный `release publish-check` требует machine-verifiable матрицу для той же версии/commit, проверяет все required targets и включает matrix/targets/certification в общий `SHA256SUMS`, Ed25519 signature и provenance boundary. Bundle без такого evidence можно собрать как CI candidate, но нельзя подтвердить как Minecraft Compatibility Release.

## Forge + NeoForge Server Bridge — 0.14.7

Forge и NeoForge 1.21.1 работают как независимые `kind=forge` и `kind=neoforge` ServerBridge nodes. Оба мода используют штатный pre-world `PlayerNegotiationEvent` как async login gate, общий bounded network runtime и локальную Ed25519 identity. Release `0.14.7+` требует отдельные `forgeSha256` и `neoforgeSha256`; artifacts и identities платформ не взаимозаменяемы.

## Fabric Server Bridge — 0.14.6

Fabric 1.21.1 работает как отдельный `kind=fabric` ServerBridge node. Мод подключается только на сервере, использует Fabric API login synchronizer для fail-closed асинхронной проверки login, хранит private Ed25519 key локально и передаёт Backend только signed Protocol v2 requests. Release `0.14.6+` требует отдельный `fabricSha256`; Fabric JAR не взаимозаменяем с Bukkit/proxy artifacts.

## ServerBridge 0.14.5 Proxy family

Velocity, BungeeCord и Waterfall используют общий production proxy runtime с Ed25519 node identity, signed Protocol v2 requests, artifact SHA-256 enforcement и one-time join tickets. Для BungeeCord/Waterfall выпускаются отдельные JAR; platform mismatch fail-closed. Production release 0.14.5 требует hashes всех proxy и Bukkit-family artifacts.


## Bukkit family — 0.14.4

`0.14.4` переводит Bukkit-совместимые ServerBridge-плагины на один production runtime `bukkit-family-common` и пять platform-matched artifacts: Bukkit/CraftBukkit, Spigot, Paper, Purpur и Folia. Общий runtime выполняет Ed25519 node authentication, SHA-256 self-measurement, heartbeat, one-time join validation, fail-closed login enforcement и diagnostics; платформенные JAR содержат только явный runtime discriminator и descriptor. JAR от другой платформы не запускается молча: mismatch приводит к отключению plugin.

Folia не использует Bukkit scheduler для backend I/O: heartbeat/reload выполняются собственным bounded daemon executor, а async pre-login остаётся сетевой границей авторизации. Release policy `0.14.4+` требует отдельный SHA-256 allowlist для `velocity`, `bukkit`, `spigot`, `paper`, `purpur` и `folia`. Migration `0024_bukkit_family_0144` расширяет PostgreSQL kind constraint без изменения существующих node identities/tickets; production E2E запускает реальные Spigot/Paper/Purpur/Folia server artifacts и проверяет allow → replay deny → revoke → deny.

## Cryptographic Node Identities — 0.14.2

`0.14.2` заменяет ServerBridge shared bearer credentials на Ed25519 node identity. Приватный ключ создаётся и хранится локально bridge-плагином в `node-identity.properties`; Backend получает только raw public key/fingerprint и `identityEpoch`. Каждый privileged request подписывает canonical method/path/body hash вместе с Unix timestamp и 192-bit nonce. PostgreSQL атомарно consume-ит nonce, поэтому повтор корректно подписанного запроса отклоняется.

Migration `0022_serverbridge_crypto_node_identities_0142` удаляет legacy token hashes, переводит существующие 0.14.1 nodes в `identity-enrollment-required` и инвалидирует активные join tickets. Для upgrade установите bridge 0.14.2, получите его `publicKey`/fingerprint из startup log и административно вызовите `/api/v1/server-bridge/servers/{serverId}/rotate-identity`; после этого node получает новый `identityEpoch` и становится `active`. Protocol v2, PostgreSQL source of truth и atomic one-time join semantics из 0.14.1 сохраняются.

## NeverGuard Release — 0.14.0

`0.14.0` переводит NeverGuard из набора platform implementations в единый production release boundary. Windows, Linux и macOS продолжают использовать authenticated IPC v4; после handshake Desktop обязательно получает authenticated `status` от реально запущенного Guard и сверяет `productVersion`, platform identity и protocol version до дальнейших команд.

Backend для `0.14+` принимает только `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` schema 2.0. Policy хранит **точные пары** SHA-256 Desktop+NeverGuard отдельно для `windows`, `linux`, `macos`, поэтому hash одного разрешённого Guard больше нельзя комбинировать с Desktop из другой разрешённой сборки. Release identity (`schema/protocol/platform`) также сохраняется в one-time challenge/ticket binding и повторно учитывается live Minecraft/ServerBridge integrity policy.

Каждый platform builder создаёт собственный v2 fragment. После финальной vendor signing используйте `scripts/release/merge-guard-release-policy.py --windows ... --linux ... --macos ... --output GUARD_RELEASE_POLICY.json`: production merger требует Authenticode Windows, Developer ID + notarization macOS и полный набор трёх платформ. Полученный JSON целиком задаётся в `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`.

## Сертификация Cross-platform Guard release — 0.13.9

`0.13.9` вводит единый certification boundary поверх production NeverGuard реализаций Windows, Linux и macOS. Каждый platform CI job обязан завершить native Guard tests, integration test, clippy/release build, platform production gate и package verification, после чего создаёт `guard-ci-result.json` для exact commit/run с SHA-256 package, Desktop, Guard, package manifest и release allowlist. Aggregate job принимает релиз только при PASS всех трёх обязательных targets.

Финальный release не пересобирает сертифицированные platform artifacts: `scripts/guard_ci/stage_release.py` переносит именно outputs прошедшего CI и повторно сверяет их хэши. Для `0.13.9+` `nl release publish-check` требует `GUARD_CI_TARGETS.json`, `GUARD_CI_MATRIX.json`, `GUARD_CI_CERTIFICATION.json` и заново хэширует каждый сертифицированный Windows/Linux/macOS artifact уже внутри подписанного bundle. CI evidence не заменяет production Authenticode/Developer ID/notarization и явно не утверждает владение vendor signing credentials.

## NeverGuard macOS production — 0.13.8

macOS использует отдельный native NeverGuard boundary: authenticated Unix-domain socket protocol v4, kernel peer PID/UID validation, `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, parent-exit kqueue watch и отдельную Minecraft process group. Integrity Evidence/Guard Attestation имеют собственные macOS schemas и включают SHA-256 Mach-O, process boundary, code signature, Hardened Runtime и library validation; Backend проверяет их независимо от Windows/Linux policy.

Production package строится `scripts/release/build-macos-desktop.sh`: universal `arm64 + x86_64` `.app`, Developer ID Application signing, Hardened Runtime, notarization/stapling и Gatekeeper assessment. Перед spawn Guard Desktop fail-closed проверяет `MACOS_PACKAGE_MANIFEST.json`, expected signing identifiers/Team ID, подписи и notarization status. `--allow-ad-hoc` предназначен только для CI/development artifact и не является production-runnable package.

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
- **ServerBridge** — реальные плагины Velocity и Bukkit-family (Bukkit/Spigot/Paper/Purpur/Folia), собираемые против платформенного API и общего security runtime.
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

## Auth Federation 0.12

`0.12.0` — стабильный Auth Federation release. Local/SQL/HTTP/OIDC/Microsoft проходят один Connector SDK/Federation Core и разрешаются в canonical Never user до выпуска Never session; passkeys/TOTP/recovery являются auth methods/MFA, а Minecraft session создаётся только поверх canonical Never session. Generic browser providers можно явно связать через `/api/v1/auth/providers/{providerId}/link/begin|complete` без auto-link по email.

Для production upgrade примените `nl db migrate apply`, затем `nl db migrate verify`. Migration `0011_auth_federation_release_0120` гарантирует canonical local identity для каждого password-capable user и блокирует повреждение этой связи на уровне PostgreSQL. Администратор может проверить runtime federation через `GET /api/v1/admin/auth/federation/status`; `/ready` требует хотя бы один здоровый auth provider.

## NeverGuard migration, compatibility & stabilization — 0.13.10

`0.13.10` завершает стабилизацию 0.13.x после cross-platform Guard certification. Новая PostgreSQL migration `0020_guard_migration_compatibility_stabilization_01310` проверяет persisted `minecraft_sessions` Guard snapshot и fail-closed останавливает upgrade на частичных/противоречивых security rows; после этого DB сама гарантирует atomic snapshot и freshness window, совпадающее с runtime ticket policy.

Исправлена cross-platform совместимость gameplay enforcement: macOS trusted device теперь проходит ту же обязательную live reevaluation Guard integrity в Minecraft/ServerBridge, что Windows/Linux. Guard CI target result дополнительно содержит `repository`, а aggregate/release certification отклоняет перенос PASS-evidence между fork/repository даже при совпавших commit/run strings. Для реального upgrade rehearsal используется `e2e/scripts/run-guard-migration-e2e.sh`.

## Windows production hardening — 0.13.6

`0.13.6` усиливает уже рабочий NeverGuard boundary без hooks/injection. Desktop и `neverguard.exe` до основной runtime-инициализации fail-closed включают heap termination-on-corruption и ограничивают default DLL search каталогом приложения и `System32`. NeverGuard IPC поднят до protocol v4: Named Pipe остаётся local-only, но теперь создаётся с protected current-user/System ACL; hardening version/state и наличие secure ACL входят в authenticated `ready` proof.

Desktop удерживает отдельный NeverGuard Job Object с `KILL_ON_JOB_CLOSE`, поэтому аварийное завершение launcher закрывает OS-level lifetime boundary Guard. Release build создаёт `WINDOWS_PACKAGE_MANIFEST.json` после финальной сборки, а release Desktop до spawn `neverguard.exe` требует соседний regular/non-symlink artifact и сверяет size + SHA-256 обоих executable с manifest. Для production-signing `build-windows-desktop.ps1 -CodeSigningCertificateThumbprint <thumbprint>` подписывает оба PE через Authenticode **до** вычисления hashes, повторно проверяет подписи и выставляет `authenticodeRequired/requireAuthenticode=true`; runtime затем выполняет локальный WinVerifyTrust до запуска Guard.

Unsigned development package намеренно не проходит release-runtime Authenticode gate и предназначен только для CI/build validation.

Это user-mode production hardening: он уменьшает поверхность DLL hijacking, локального IPC и orphan Guard process и делает release corruption/replacement fail-closed в штатной модели. Он не является защитой от администратора/kernel attacker и не заменяет server-side Guard Attestation/allowlist из 0.13.4–0.13.5.

## Minecraft/ServerBridge integrity enforcement — 0.13.5

`0.13.5` закрывает gameplay bypass между Guard Attestation и ServerBridge. Guard-verified metadata теперь сохраняется в самой Minecraft session и live-проверяется при validate/join/hasJoined. Для Windows Guard-enforced device Desktop передаёт новый Minecraft access token в `/api/v1/session/join`; Backend сохраняет `minecraftSessionId`, поэтому ServerBridge не может принять отдельный join, не связанный с тем credential, который получил одноразовый Guard launch ticket.

Velocity и Bukkit/Spigot/Paper/Purpur/Folia дополнительно хэшируют собственный запущенный JAR (`SHA-256`) и отправляют `pluginVersion + pluginSha256` в heartbeat и `validate-join`. Backend принимает только hashes из `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`, повторно проверяет текущую policy на каждом join и сбрасывает measurement после rotation node identity. `scripts/build/bridge-plugins.sh` генерирует `BRIDGE_RELEASE_ALLOWLIST.json` из фактически собранных JAR; production Backend без этой policy не проходит конфигурационную проверку.

Удаление Guard/Desktop или ServerBridge hash из соответствующего allowlist действует как live revoke: уже созданная Minecraft/ServerBridge session перестаёт проходить Backend validation. ServerBridge JAR self-hash является application-level release enforcement и не выдаётся за TPM/kernel attestation удалённого Minecraft host.

## NeverGuard: Guard Attestation и Backend verification — 0.13.4

`0.13.4` делает NeverGuard evidence серверно проверяемым в launch flow. Backend выдаёт одноразовый challenge, Desktop передаёт его в отдельный `neverguard.exe` через authenticated IPC v3, а Guard формирует свежую attestation поверх Integrity Evidence v1 и реально применённого Windows process policy. Hardware P-256 device key подписывает каноническую привязку attestation к текущим user/device/session/binding epoch и версии launcher; приватный ключ не передаётся Backend или frontend.

Backend endpoints `POST /api/v1/auth/devices/{deviceId}/guard-attest/begin|complete` проверяют одноразовость/freshness challenge, P-256 signature, evidence/attestation digests, PID boundary, process-policy flags и точные SHA-256 `neverguard.exe`/Desktop по `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`. После успешной проверки Backend выдаёт короткоживущий single-use Guard launch ticket. Для Windows trusted device в production `/api/v1/minecraft/session` не выдаёт игровую session без валидного ticket; повторное использование ticket отклоняется.

Windows package build создаёт `GUARD_RELEASE_ALLOWLIST.json` рядом с `WINDOWS_PACKAGE_MANIFEST.json`; его значения должны быть перенесены в production configuration после финальной сборки/подписи binaries. `requireAuthenticode` можно включить только для release pipeline, где конечные файлы действительно подписаны до вычисления allowlist hashes. Эта схема является application-level Guard Attestation, а не TPM quote/Measured Boot или kernel anti-cheat.

## NeverGuard Windows: применение runtime/process policy — 0.13.3

`0.13.3` делает Windows policy исполняемой, а не декларативной. `neverguard.exe` до запуска Tokio применяет и заново проверяет process mitigations (`DynamicCode`, `ExtensionPointDisable`, `StrictHandleCheck`, `ImageLoad`, `ChildProcess`). Applied state возвращается только по authenticated IPC `process-policy`; handshake protocol v2 также привязывает policy version/enforced bit к `ready` proof.

Java/Minecraft на Windows создаётся с `CREATE_SUSPENDED`, назначается в отдельный non-breakaway Job Object с `KILL_ON_JOB_CLOSE` и `DIE_ON_UNHANDLED_EXCEPTION`, после чего NeverRuntime проверяет membership/limits и только затем выполняет `ResumeThread`. Если любой шаг enforcement не подтверждён, launch прекращается fail-closed. Job handle удерживается supervisor-ом на всём времени жизни runtime, поэтому закрытие boundary завершает связанное process tree. `ProcessStatus.windowsProcessPolicy` показывает фактически применённую policy.

Java не получает `ProhibitDynamicCode`: HotSpot JIT требует динамически сгенерированный executable code. Строгие dynamic-code/image/child-process mitigations применяются к небольшому NeverGuard process, а Minecraft runtime изолируется process-tree policy без hooks/injection.

## NeverGuard Windows Integrity Evidence v1 — 0.13.2

`0.13.2` расширяет authenticated process boundary реальным Windows Integrity Evidence v1. Evidence собирается внутри отдельного `neverguard.exe` после успешного IPC handshake и теперь является обязательным fail-closed шагом перед Windows Minecraft launch. Guard независимо проверяет фактический parent PID, хэширует собственный executable и launcher process image, фиксирует размер/mtime/process creation time, выполняет локальную Authenticode-проверку через `WinVerifyTrust`, считывает process mitigation flags через `GetProcessMitigationPolicy` и строит fingerprint загруженного module set через Toolhelp snapshot.

Payload использует schema `neverguard/windows-integrity-evidence/v1`. Canonical core получает `evidenceSha256`, а затем guard привязывает digest к текущему authenticated IPC session key через HMAC `sessionProof`. Desktop повторно проверяет schema/version, PID boundary, SHA-256 и session proof перед использованием. Команда `neverguard_integrity_evidence` возвращает уже проверенный local payload; ошибка сбора или проверки блокирует `launch_minecraft`.

Это **local evidence**, а не server-verifiable attestation: Desktop участвует в локальной IPC session и текущая версия не использует TPM quote, отдельный device-bound attestation key, kernel measurement или remote verifier. Следующий server-verifiable этап должен добавлять собственную challenge/freshness/signature boundary и не выводить удалённое доверие только из `WinVerifyTrust` или process mitigations.

## NeverGuard Windows 0.13.1

`0.13.1` добавляет первый рабочий NeverGuard boundary для Windows. Guard — отдельный `neverguard.exe`; Desktop перед каждым Minecraft launch поднимает его и fail-closed требует успешный authenticated IPC handshake. Bootstrap secret генерируется на каждый запуск и передаётся guard как 32 raw bytes через унаследованный stdin, а не через argv/environment/файл.

IPC работает через local-only Windows Named Pipe со случайным endpoint. Взаимная HMAC-SHA-256 аутентификация использует client/server nonces и отдельный session key; каждый последующий request/response подписан MAC и защищён монотонным sequence от replay/out-of-order. В `0.13.1` доступны operational commands `ping`, `status`, `shutdown`; integrity evidence и server-verifiable guard attestation относятся к следующим этапам NeverGuard и здесь намеренно не заявляются.

Windows package собирается командой:

```powershell
./scripts/release/build-windows-desktop.ps1
```

ZIP содержит Desktop executable и обязательный соседний `neverguard.exe`; CI на `windows-2022` запускает реальный process-boundary integration test перед созданием release candidate.

## Device Trust Release 0.13.0

`0.13.0` завершает roadmap Device Trust и делает trust evidence частью официального подписанного release bundle. Схема не получает пустую migration: production baseline остаётся `0018_device_trust_stabilization_01210`, а Backend `/ready` и Device Trust E2E обязаны подтвердить её перед PASS.

Public matrix требует PostgreSQL lifecycle E2E и native Linux/Windows/macOS key-policy tests. Для официальной публикации `nl release publish-check` проверяет не только Minecraft Compatibility certification, но и `DEVICE_TRUST_TARGETS.json`, `DEVICE_TRUST_MATRIX.json`, `DEVICE_TRUST_CERTIFICATION.json`, привязанные к той же версии и source commit. `build-release.sh` принимает public matrix через `NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE`; без certification bundle остаётся release candidate.

Backend публикует machine-readable `deviceTrustRelease` contract в `/api/v1/auth/capabilities`: server-authoritative binding epoch, device-bound refresh, risk actions, Minecraft/ServerBridge enforcement, permanent revocation, dual-proof rotation и phishing-resistant recovery. P-256 protocol proof не выдаётся за vendor TPM/Secure Enclave provenance.

## Migration + stabilization 0.12.10

`0.12.10` является stabilization-релизом Device Trust schema и production-upgrade path. Migration `0018_device_trust_stabilization_01210.sql` исправляет PostgreSQL challenge-purpose constraint для реально используемых `key-rotate`/`key-recover`, переводит optional device references с empty-string sentinel на SQL `NULL`, нормализует безопасные legacy revoked/challenge states и затем устанавливает ownership/lifecycle constraints между trusted devices, auth sessions и Minecraft sessions.

Upgrade выполняется fail-closed: cross-user или структурно противоречивые связи не маскируются автоматическим repair, а останавливают migration до установки новых constraints. Отдельный `e2e/scripts/run-device-trust-migration-e2e.sh` воспроизводит exact `0.12.9` schema (`0001..0017`), применяет shipping CLI migration/verify и проверяет post-upgrade PostgreSQL enforcement. Public Device Trust matrix `0.12.10` принимает protocol PASS только вместе с evidence этого upgrade.

Для strict локальной проверки при наличии Docker/PostgreSQL client:

```bash
bash e2e/scripts/run-device-trust-migration-e2e.sh
bash e2e/scripts/run-device-trust-e2e.sh
```

## Device Trust E2E и публичная trust matrix 0.12.9

`0.12.9` добавляет отдельный production E2E для всей Device Trust цепочки и публичную CI-матрицу. `e2e/scripts/run-device-trust-e2e.sh` запускается против production-configured PostgreSQL/Redis Backend и реальными Ed25519/P-256 ключами проверяет registration/replay deny, binding epoch, signed refresh, dual-proof rotation, permanent fingerprint tombstone, ServerBridge invalidation, risk step-up, hardware-key challenge-response protocol, recovery prerequisite и revoke cascade.

Публичные цели находятся в `device-trust/targets.json` и не содержат ручного поля PASS/FAIL. Workflow `.github/workflows/device-trust.yml` запускает PostgreSQL protocol target и native Tauri/key-policy tests на Linux/Windows/macOS, после чего `scripts/device_trust/matrix.py` принимает только evidence той же версии, exact commit и Actions run ID. Итоговые `matrix.json` и `matrix.md` публикуются в Actions Summary и artifact. Aggregator дополнительно сверяет SHA-256 каждого заявленного evidence-файла; отсутствующий, изменённый, неполный или чужой result делает matrix failed.

Матрица не завышает assurance: CI P-256 case доказывает server-side challenge-response владение зарегистрированным ключом, но не vendor TPM/Secure Enclave provenance. Native platform targets доказывают compile/test path; headless runner не считается доказательством фактического OS secure-storage/HSM runtime конкретного устройства.

Локальная проверка definition/aggregator:

```bash
python3 scripts/device_trust/matrix.py validate --targets device-trust/targets.json
python3 scripts/device_trust/test_matrix.py
```

Production protocol E2E при наличии Docker/PostgreSQL client:

```bash
bash e2e/scripts/run-device-trust-e2e.sh
```

Подробности: `device-trust/README.md`.

## Кроссплатформенное усиление ключей 0.12.8

`0.12.8` добавляет production lifecycle для плановой ротации и восстановления потерянного device key. Rotation требует proof старым и новым ключом; recovery требует свежий phishing-resistant WebAuthn/passkey step-up и proof staged-новым ключом. Backend всегда создаёт новую device identity, увеличивает `binding_epoch`, оставляет старый fingerprint permanent tombstone и отзывает связанные старой identity sessions/refresh/Minecraft credentials.

Desktop/Tauri выполняет замену двухфазно (`stage → server ceremony → commit`) и умеет reconcile interrupted commit. Hardware P-256 ключи используют generation-specific labels, поэтому reset/rotation на TPM/Secure Enclave не переиспользует прежний ключ. При server-side revoke/missing device локальный key не уничтожается автоматически: используется recovery flow. API: `/api/v1/auth/devices/key-rotation/begin`, `/{deviceId}/key-rotation/complete`, `/key-recovery/begin`, `/{deviceId}/key-recovery/complete`.

## Minecraft / ServerBridge trust enforcement 0.12.7

`0.12.7` применяет Device Trust к самому игровому входу. Официальный `/api/v1/minecraft/session` требует active Never session, привязанную к verified trusted device, и допустимое risk decision. Minecraft credential сохраняет snapshot `trusted_device_id + binding_epoch`; ServerBridge join сохраняет тот же snapshot вместе с `project/profile/channel`.

При `validate`, Minecraft `join/hasJoined` и ServerBridge `validate-join/has-joined` Backend заново сверяет текущую parent session, device state, binding epoch и risk action. Re-bind или permanent revoke инвалидирует старый credential; `reattest` и `step-up` временно блокируют игровой вход до восстановления trust. Server-side plugin requests не изменяют IP/User-Agent risk игрока — они только применяют уже рассчитанное состояние. Legacy Yggdrasil authenticate остаётся совместимым, но фактический Minecraft `/join` без trusted device fail-closed, поэтому старый auth path не является bypass.

Migration `0016_minecraft_serverbridge_trust_0127.sql` добавляет persisted trust snapshot для `minecraft_sessions`. ServerBridge дополнительно проверяет `channel` наряду с project/profile. Velocity и Bukkit/Spigot/Paper/Purpur/Folia показывают конкретную причину trust deny и не имеют локального флага, отключающего Backend policy.

## Привязка сессии к устройству и интеграция риска 0.12.6

`0.12.6` связывает access/refresh lifecycle с реальным server-side состоянием trusted device. Persistent `binding_epoch` увеличивается при device bind/re-bind и входит в access JWT; Backend сверяет epoch, `device_id` и `device_trust` с текущей session, поэтому старый pre-bind token отклоняется сразу после смены binding.

Для bound-session `/api/v1/auth/refresh` теперь требует подпись текущим device key. Desktop выполняет её native-командой `sign_session_refresh`; signed payload содержит session/device/epoch и только SHA-256 refresh token. Risk engine хранит score/action (`allow|step-up|reattest|revoke`): network drift требует step-up на sensitive operations, stale hardware attestation — повторной attestation, а missing/revoked device или reuse refresh token приводит к revoke. PostgreSQL schema обновляется migration `0015_session_device_risk_0126.sql`.

## Device Management 0.12.5 — управление и необратимый revoke

`0.12.5` добавляет рабочий lifecycle trusted devices поверх Device Trust 0.12.1–0.12.4. `GET /api/v1/auth/devices?status=active|revoked` возвращает registry с признаком текущего устройства; `POST /api/v1/auth/devices/{deviceId}/revoke` необратимо отзывает конкретное устройство, а `POST /api/v1/auth/devices/revoke-others` сохраняет текущее verified device и отзывает остальные. Старый fingerprint после revoke остаётся tombstone и не может быть повторно зарегистрирован.

В PostgreSQL revoke выполняется транзакционно и каскадирует на Never sessions, refresh families/tokens, Minecraft sessions и незавершённые device challenges; связанные ServerBridge joins инвалидируются сразу после commit. Desktop показывает registry, умеет rename/revoke/revoke-others и при self-revoke удаляет local device key + auth session из OS secure storage. Admin registry/revoke доступен через `/api/v1/admin/auth/devices*`; admin revoke требует fresh phishing-resistant step-up. Новая migration не нужна — 0.12.5 использует уже существующую persistent schema и усиливает runtime semantics.

## Device Trust 0.12.4 — проверка challenge-response

`0.12.4` добавляет свежую проверяемую ceremony поверх hardware-bound P-256 identity из `0.12.3`. После обычного registration/session-bind Backend выдаёт уже привязанной сессии отдельный short-lived single-use attestation challenge. Tauri подписывает canonical `NeverLauncher Device Attestation v1` payload тем же non-exportable hardware key; software Ed25519 key в этот flow не допускается.

Успешная проверка сохраняет `attestationState=verified`, `attestationMethod=challenge-response-v1` и 12-часовое freshness window. Пока окно действительно, device assurance отражается как `challenge-response-attested`; после expiry API/JWT эффективно возвращают `proof-of-possession` до новой ceremony. Migration `0014_challenge_response_attestation_0124.sql` добавляет persistent state и purpose `attest` в существующий challenge registry.

Это подтверждает свежое владение зарегистрированным hardware key, но не подменяет vendor remote attestation: текущий signer API не даёт NeverLauncher TPM quote/Secure Enclave attestation certificate, поэтому `hardwareProvider` остаётся описательной metadata, а ответы явно содержат `hardwareProvenance=not-remotely-verified`. Device attestation не повышает RBAC/MFA/auth strength и не заменяет WebAuthn.

`0.12.3` остаётся базовым hardware identity layer: platform Secure Enclave/TPM → P-256 public key + ECDSA proof, с явным Ed25519/software fallback при отсутствии настоящего hardware backend.

## Device Trust 0.12.2

`0.12.1` добавил persistent registry и Ed25519 proof-of-possession; `0.12.2` доводит device key до официального Desktop-клиента. Tauri создаёт отдельный Ed25519 key для пары `Backend + canonical user`, хранит private seed только в native OS secure storage и подписывает server challenge внутри Rust boundary. React получает только public key/fingerprint/signature; private key не попадает в Backend, конфиг или `localStorage`.

После login Desktop автоматически выполняет регистрацию нового trusted device либо `verify/begin|complete` уже известного device id и сохраняет обновлённый access token с device claims в OS credential store. Revoke устройства по-прежнему отзывает связанные Never sessions/refresh families. Эта версия подтверждает software key possession + OS secure storage, но **не** заявляет hardware-bound identity/attestation — TPM/Secure Enclave/Windows Hello относятся к следующим этапам.

Production upgrade: `nl db migrate apply && nl db migrate verify`. Migration `0012_device_trust_core_0121` создаёт `trusted_devices`, single-use `device_challenges` и отдельную связь trusted device с `auth_sessions`.

## Minecraft Auth Compatibility 2.0

С `0.11.10` federation/migration stability является исполняемым release gate. `python3 scripts/test/federation-e2e.py` прогоняет Local/SQL/HTTP/OIDC/Microsoft/passkey через canonical session и Minecraft compatibility flow, а `bash e2e/scripts/run-federation-postgres-e2e.sh` проверяет restart и multi-instance refresh/revoke/replay на PostgreSQL. Перед production upgrade используйте `nl db migrate apply`, затем `nl db migrate verify`; verify fail-closed отклоняет unknown/future migrations, незапечатанные checksum и checksum drift.

С `0.11.9` login identity и Minecraft identity разделены. Local/SQL/HTTP/OIDC/Microsoft/passkey приводят к одному canonical Never user; из действующей Never session Desktop получает отдельную Minecraft session через `/api/v1/minecraft/session`. Игровой access token opaque и server-side хранится только в виде hash, а стабильный Minecraft UUID строится из immutable Never user ID, а не email.

NeverRuntime передаёт полученные UUID/token в реальный Minecraft launch. Если подписанный release manifest содержит `authlib-injector*.jar`, runtime подключает его как `-javaagent` к Backend, где доступны Yggdrasil-compatible `/authserver/*` и `/sessionserver/session/minecraft/*`. Начиная с 0.12.7 Minecraft token дополнительно привязан к trusted device и `binding_epoch`: re-bind/revoke/risk enforcement делает его непригодным для validate/join/hasJoined. ServerBridge применяет ту же live trust policy и pin project/profile/channel для защищённых серверов.

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

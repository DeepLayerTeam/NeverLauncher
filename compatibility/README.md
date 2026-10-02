# Minecraft compatibility

NeverLauncher 0.17.9 — **Cross-platform Loaders**. Fabric 26.3, Quilt 26.3, Forge 26.3 и NeoForge 26.2 имеют обязательную шестиплатформенную certification-сетку: Windows/Linux/macOS × x64/ARM64. PASS требует exact OS/arch JRE, target-aware materialization, native files только в `natives/<os>/<arch>`, совпадающий `nativesDirectory` из NeverRuntime, deterministic `nativeTreeSha256` и actual loader client launch. Release certification хранит 24 `crossPlatformLoaderTargets`; historical loader release grids остаются отдельными Linux x64 regression gates.

NeverLauncher 0.17.7 — **Loader Resolution & Pinning**. Для каждого required Fabric/Quilt/Forge/NeoForge target PASS требует concrete immutable loader version, `resolutionLockSha256`, `resolutionSourceSha256`, `reproducibilitySha256`, проверки `loaderPinned`/`reproducibleResolution` и raw `<loader>-resolution-lock.json`. Client/integration E2E выполняет второй materialize через тот же lock: mutable selector больше не может незаметно выбрать другую версию, а изменённые upstream profile/installer/runtime profile блокируют certification.

NeverLauncher 0.17.6 — **NeoForge Compatibility II** поверх Forge/Fabric/Quilt/Minecraft Compatibility II GA. Обязательная NeoForge-линия: 22 release targets `1.20.1`–`26.2`, exact Java 17/21/25, Linux x86_64; `1.21.1` остаётся `integration`, остальные — `client`. PASS требует реальный processor installer, package integrity, immutable resolved NeoForge version и actual client launch через NeverRuntime.

NeverLauncher 0.17.5 — **Forge Legacy 1.7.10 LaunchWrapper/FML** поверх Forge Legacy 1.12.2 / Forge Modern / Fabric / Quilt / Minecraft Compatibility II GA. Обязательная цель: `1.7.10`, Java 8, `client`, Linux x86_64, `latest-stable` selector с concrete immutable Forge version. PASS требует V1 universal installer, SHA-verified universal JAR, `net.minecraft.launchwrapper.Launch`, `cpw.mods.fml.common.launcher.FMLTweaker`, нормализованный parent Vanilla 1.7.10 profile, package integrity и actual client launch через NeverRuntime.

NeverLauncher 0.17.4 — **Forge Legacy 1.12.2** поверх Forge Modern / Fabric Compatibility II / Minecraft Compatibility II GA: Vanilla Compatibility Baseline II + Legacy Vanilla Java 8 + Java 16/17 + Java 21 + Java 25 + Cross-platform Vanilla + Actual Client E2E II + Compatibility Hardening + certified JRE binary base. Release compatibility формируется только из фактической Mojang materialization, package integrity, Compatibility Engine resolution, exact Java/JRE attestation и запуска настоящего Minecraft Java Client. Representative targets дополнительно обязаны пройти реальный join на официальный Mojang server той же версии.

Обязательная Forge Legacy certification 0.17.4: `1.12.2`, Java 8, `client`, Linux x86_64, `latest-stable` selector с concrete immutable Forge version в evidence. PASS требует реальный V1 universal installer либо официальный repacked empty-processor 1.12.2 layout, проверенный universal JAR, сохранённый LaunchWrapper/FMLTweaker profile, package verify и actual client launch через NeverRuntime.

Обязательная Vanilla release-line и cross-platform certification 0.17.0:

| Minecraft | Java | scope |
| --- | ---: | --- |
| 1.0 (`1.0.0` CLI alias) | 8 | client |
| 1.1 | 8 | client |
| 1.2.5 | 8 | client |
| 1.3.2 | 8 | client |
| 1.4.7 | 8 | client |
| 1.5.2 | 8 | client |
| 1.6.4 | 8 | client |
| 1.7.10 | 8 | client |
| 1.8.9 | 8 | client |
| 1.9.4 | 8 | client |
| 1.10.2 | 8 | client |
| 1.11.2 | 8 | client |
| 1.12.2 | 8 | client |
| 1.13.2 | 8 | client |
| 1.14.4 | 8 | client |
| 1.15.2 | 8 | client |
| 1.16.5 | 8 | client |
| 1.17.1 | 16 | client |
| 1.18.2 | 17 | client |
| 1.19.4 | 17 | client |
| 1.20.1 | 17 | client |
| 1.20.2 | 17 | client |
| 1.20.4 | 17 | client |
| 1.20.5 | 21 | client |
| 1.20.6 | 21 | client |
| 1.21 | 21 | client |
| 1.21.1 | 21 | integration |
| 1.21.2 | 21 | client |
| 1.21.3 | 21 | client |
| 1.21.4 | 21 | client |
| 1.21.5 | 21 | client |
| 1.21.6 | 21 | client |
| 1.21.7 | 21 | client |
| 1.21.8 | 21 | client |
| 1.21.9 | 21 | client |
| 1.21.10 | 21 | client |
| 26.1 | 25 | client |
| 26.1.1 | 25 | client |
| 26.1.2 | 25 | client |
| 26.3 | 25 | client |


## NeoForge Compatibility II — 0.17.6

Для `>= 0.17.6` обязательны 22 stable NeoForge targets: `1.20.1`–`1.20.6`, `1.21`–`1.21.11`, `26.1`, `26.1.1`, `26.1.2`, `26.2`. Java mapping: 1.20.1–1.20.4 → 17, 1.20.5–1.21.11 → 21, 26.x → 25. Историческая 1.20.1-линия разрешается из `net.neoforged:forge`; 1.20.2+ — из `net.neoforged:neoforge`; prerelease versions не удовлетворяют `latest-stable`.

Client scope выполняет `nl runtime neoforge-package`, реальный installer processor pipeline, package verify и NeverRuntime actual-client launch. Release evidence сохраняет `neoforge-install.json`, `neoforge-certification.json` и отдельный `neoForgeVersions` coverage; bundle verification повторно пересчитывает coverage из matrix/targets.

## Forge Modern — 0.17.3

Для `>= 0.17.3` обязательны 43 processor-based Forge release targets от `1.13.2` до `26.3`: Java 8 до `1.16.5`, Java 16 для `1.17.1`, Java 17 для `1.18`–`1.20.4`, Java 21 для `1.20.6`–`1.21.11`, Java 25 для `26.x`. `1.21.1` остаётся `scope=integration`; остальные Forge targets — Linux/x86_64 `scope=client`. Forge `1.13`/`1.13.1` не входят в Modern grid, потому что certification требует processor-based installer format.

Client scope выполняет production installer path: `nl runtime forge-package` загружает checksum-verified Forge installer, извлекает installer data и embedded Maven artifacts, материализует libraries, исполняет client processors на exact target Java, проверяет outputs, пишет generated Forge version profile и собирает локальный package. Затем `nl client verify` проверяет package tree, а NeverRuntime запускает concrete materialized Forge main class. PASS требует processor execution evidence, installer/profile SHA-256 и immutable resolved Forge version.

## Quilt Compatibility II — 0.17.2

Для `>= 0.17.2` обязательны 48 stable Quilt release targets от `1.14` до `26.3`. Java binding совпадает с фактическими Minecraft runtime requirements: `1.14`–`1.16.5` → Java 8, `1.17`–`1.17.1` → Java 16, `1.18`–`1.20.4` → Java 17, `1.20.5`–`1.21.11` → Java 21, `26.1`–`26.3` → Java 25. `1.21.1` остаётся `scope=integration`; остальные Quilt targets — Linux/x86_64 `scope=client`.

Client scope выполняет production path: `nl runtime quilt-package` получает Mojang client и официальный Quilt Meta v3 profile, материализует и hash-verifies Maven libraries, package verify проверяет локальное дерево, а NeverRuntime запускает materialized Quilt profile (`KnotClient`) на exact target Java. `latest-stable` разрешается только в конкретный Loader; для Quilt Meta без Fabric-style `stable` field prerelease semver (`beta`, `rc` и т.п.) не считается stable. Пустой stable set приводит к fail-closed ошибке, а не к выбору первого Loader.

Compatibility aggregation и release certification требуют полный Quilt grid и отдельные `quilt-install.json` / `quilt-certification.json` evidence для client targets. Missing/duplicate release, wrong Java/scope/platform, mutable resolved Loader, incomplete package evidence или failed actual-client launch блокируют release.

## Fabric Compatibility II — 0.17.1

Для `>= 0.17.1` обязательны 48 stable Fabric release targets от `1.14` до текущего stable `26.3`. Java binding: `1.14`–`1.16.5` → Java 8, `1.17`–`1.17.1` → Java 16, `1.18`–`1.20.4` → Java 17, `1.20.5`–`1.21.11` → Java 21, `26.1`–`26.3` → Java 25. `1.21.1` остаётся `scope=integration`; остальные Fabric targets — Linux/x86_64 `scope=client`.

Client scope является исполняемым: `nl runtime fabric-package` получает официальный Mojang client + Fabric Meta profile, материализует и hash-verifies Maven libraries, package verify проверяет локальное дерево, а NeverRuntime запускает конкретный materialized Fabric profile (`KnotClient`) на exact target Java. Selector `latest-stable` допустим только во входном target: опубликованный result обязан содержать конкретный immutable Loader version. Aggregator и release certification отклоняют отсутствующую/дублированную версию, wrong Java/scope/platform, mutable Loader result, неполное evidence и failed actual-client launch.


Cross-platform gate для Minecraft 26.3 дополнительно требует шесть native-host targets:

| OS | x64 | ARM64 |
| --- | --- | --- |
| Linux | `vanilla-26.3-linux-x64` | `vanilla-26.3-linux-arm64` |
| Windows | `vanilla-26.3-windows-x64` | `vanilla-26.3-windows-arm64` |
| macOS | `vanilla-26.3-macos-x64` | `vanilla-26.3-macos-arm64` |

Каждый target фиксирует `platform-runtime.json` с detected OS/arch. `platformMatched=false`, запуск на runner другой архитектуры или отсутствие host evidence делает matrix/release certification невалидной. Extracted natives изолируются в `natives/<os>/<arch>`.


## Compatibility Hardening — 0.16.11

`0.16.11` усиливает уже исполняемый materialization/runtime path без добавления фиктивных compatibility targets. Artifact cache считается доверенным только после повторной проверки ожидаемого SHA-1/size; повреждённые entries переводятся в bounded quarantine. Прерванный `.nlpart` продолжается через HTTP Range только при валидном `206 Content-Range`; итоговый файл всё равно публикуется только после полного Mojang SHA-1/size check. Полностью скачанный и уже совпадающий `.nlpart` может быть атомарно восстановлен без сети.

Verified exact-version Mojang metadata хранится отдельно с SHA-1/SHA-256/size/identity binding и используется только как outage recovery для конкретной версии. `latest`, `latest-release` и snapshot selectors не получают stale fallback; если authoritative manifest успешно отвечает, но версии в нём нет, локальный snapshot также не resurrected. Asset index и server/client artifacts используют checksum-bound local cache, а corrupt copies не перезаписываются молча.

Native archives имеют limits на entry count, per-entry uncompressed size и total extracted bytes; traversal/symlink/non-regular entries отклоняются. Natives сначала строятся в staging и только после полной проверки transactionally заменяют `natives/<os>/<arch>`; legacy virtual assets и `resources/` проходят тот же staging/swap принцип, поэтому ошибка построения не уничтожает предыдущий рабочий tree. Remote URL policy отклоняет credentials, fragments и небезопасные private literal upstreams без explicit opt-in.

Managed Java record schema `1.2` дополнительно хранит SHA-256 фактического Java executable и повторно проверяет его до `java -version`. Adoptium/Managed JRE requests имеют bounded retry для transient HTTP/network failures, redirects не могут понизить HTTPS, повреждённые archives quarantined, а уже полностью скачанный verified partial может быть atomically promoted после сбоя.

Actual Client E2E II для 0.16.10 дополнительно требует пять matching client/server pairs:

| Minecraft | Java | matching target |
| --- | ---: | --- |
| 1.7.10 | 8 | `vanilla-1.7.10-linux-x64` |
| 1.17.1 | 16 | `vanilla-1.17.1-linux-x64` |
| 1.20.4 | 17 | `vanilla-1.20.4-linux-x64` |
| 1.21.10 | 21 | `vanilla-1.21.10-linux-x64` |
| 26.3 | 25 | `vanilla-26.3-linux-x64` |

Для этих targets `actualClient=true` недостаточно. CI получает `downloads.server` из той же verified Mojang `version.json`, проверяет server JAR, запускает его на том же exact Java major, направляет реальный клиент на ephemeral localhost port и требует фактический world join. Evidence содержит `vanilla-server-install.json`, `matching-server.json` и server log; `serverVersionMatched`, `serverHealthy` и `clientJoinedServer` должны быть `true`.

NeoForge остаётся обязательным на 1.21.1/Java 21 с `scope=integration`; Fabric с 0.17.1 и Quilt с 0.17.2 сертифицируются полными линиями 1.14–26.3, а Forge Modern с 0.17.3 — processor-based линией 1.13.2–26.3. Для всех трёх широких loader-линий 1.21.1 сохраняет integration scope. Для loader targets mutable `latest-stable` разрешается до выполнения target, а опубликованный result обязан содержать конкретную immutable версию loader.

## Исполняемые scope

`client` используется для historical Vanilla, Fabric, Quilt и Forge release targets, где compatibility подтверждается фактическим client launch без Paper integration world-join. Для каждого такого target CI выполняет рабочий путь:

```text
official Mojang version metadata
 -> materialize client.jar/libraries/assets/natives
 -> local SHA-256 package verify
 -> resolve Compatibility Engine metadata
 -> verify exact target Java major
 -> launch real Minecraft main class on the native host (Xvfb on Linux)
 -> require process to stay healthy until certification window or exit successfully
 -> store runtime log + machine-verifiable evidence
```

Это не metadata-only gate: `neverruntime certify-vanilla` запускает фактический материализованный клиент. Для pre-1.6 metadata materializer строит `assets/virtual/pre-1.6`, NeverRuntime формирует legacy session id для `${auth_session}` и разрешает `${game_assets}` и передаёт фактический virtual-assets path. Для legacy metadata без `arguments.jvm` Compatibility Engine добавляет launcher JVM baseline (`java.library.path`, launcher identity и classpath), поддерживает `${user_properties}`/`${profile_properties}`, а classifier-only native libraries не попадают в classpath как несуществующие JAR. Release-диапазон 1.0–1.16.5 получает resolved Java 8 даже при отсутствии поля `javaVersion`.

`integration` сохраняет полный production E2E:

```text
upstream metadata / installer
 -> materialization
 -> local SHA-256 package verify
 -> canonical /api/v1 upload
 -> Ed25519 signed immutable release
 -> clean NeverRuntime sync
 -> pinned signature + file integrity verification
 -> exact Java major
 -> Xvfb actual Minecraft client
 -> Paper 1.21.1 world join
 -> launcher session revoke
 -> subsequent join denied
```

Workflow `.github/workflows/compatibility.yml` устанавливает Java каждого target отдельно от Java 21 build tooling, фиксирует реальный executable и detected major, запускает target и публикует `compatibility-result.json` вместе с evidence. Агрегатор отклоняет отсутствующий/дублированный target, Java mismatch, scope mismatch, несовпадение commit/run ID, mutable loader result и неполный actual-client evidence.

Для `>= 0.17.3` Forge Modern дополняет Quilt Compatibility II, Fabric Compatibility II и GA; сама Vanilla GA maintenance revision v3 требует минимум 109 обязательных Vanilla targets / 104 уникальных Vanilla releases и JRE attestation для каждого PASS: SHA-256 фактического `java`/`java.exe`, vendor, runtime version, VM, `java.home`, exact Java major и host OS/arch. Mandatory base сохраняет полный Legacy Vanilla v1 grid из 53 release ID `1.2.1`–`1.16.4` на Java 8, v2 Java-transition grid (`1.17` на Java 16; `1.18`, `1.18.1`, `1.19`, `1.19.1`, `1.19.2`, `1.19.3`, `1.20`, `1.20.3` на Java 17) и добавляет v3 releases `1.21.11` на Java 21 и `26.2` на Java 25. Все v1/v2/v3 additions обязаны быть Linux/x86_64 client targets. `matrix.json` агрегирует concrete `jreBase`, а release certificate повторно связывает этот набор с target evidence.

Для product version `>= 0.16.2` сохраняется Baseline II. Начиная с `0.16.3`, агрегатор и CLI release certification fail-closed требуют десять Java 8 release-line targets 1.7.10–1.16.5. Для `>= 0.16.4` дополнительно обязательны pre-1.7 targets `1.0`, `1.1`, `1.2.5`, `1.3.2`, `1.4.7`, `1.5.2`, `1.6.4`, `1.7.10`. Для `>= 0.16.6` обязательна Java 16/17 линия `1.17.1`, `1.18.2`, `1.19.4`, `1.20.1`, `1.20.2`, `1.20.4`. Для `>= 0.16.7` дополнительно обязательна Java 21 линия `1.20.5`, `1.20.6`, `1.21`, `1.21.1`–`1.21.10`. Для `>= 0.16.8` обязательны Java 25 targets `26.1`, `26.1.1`, `26.1.2`, `26.3`; materializer и NeverRuntime независимо отклоняют отсутствующий или неверный `javaVersion.majorVersion`. В `0.17.0v3` тем же fail-closed production path отдельно закреплены `1.21.11`/Java 21 и `26.2`/Java 25. Для `>= 0.16.9` `26.3` дополнительно обязателен на Linux/Windows/macOS x64+ARM64 с точным host-platform evidence и architecture-isolated natives. Для `>= 0.16.10` пять representative Linux/x64 Vanilla targets обязаны иметь `matchingServer=true` и доказанный join на verified Mojang server той же версии. Для `>= 0.16.11` release policy дополнительно фиксирует compatibility hardening, а repository gate требует resumable checksum-verified downloads, exact-version metadata recovery без stale aliases, quarantine/transactional natives и Managed Java executable integrity. В `0.17.0v1` materializer и NeverRuntime также fail-closed фиксируют Java 8 для всей Legacy Vanilla 1.x линии до `1.16.5` и отклоняют metadata без исполняемых `arguments.game`/`minecraftArguments`. Java coverage — `8/16/17/21/25`; все пять Vanilla/loader families и exact target binding обязательны. Удалить любую обязательную release-line или matching-server цель из `targets.json` и получить зелёный release невозможно.

Локальная проверка определения и агрегатора:

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

## Release certification

При сборке официального release CLI повторно валидирует `matrix.json` вместе с `compatibility/targets.json` и создаёт `COMPATIBILITY_CERTIFICATION.json`. Для 0.17.3 certification дополнительно фиксирует полные Fabric и Quilt 1.14–26.3 grids, processor-based Forge 1.13.2–26.3 grid и concrete resolved Loader versions; Vanilla GA часть фиксирует required/passed targets, не менее 109 Vanilla targets / 104 уникальных release IDs, полный 53-release Legacy Vanilla grid, полный v2 Java 16/17 grid, обязательные `1.21.11`/Java 21 и `26.2`/Java 25, пять mandatory matching-server pairs, Java majors, concrete certified JRE builds (vendor/runtime/SHA-256/OS/arch/target count), scopes, SHA-256 target definition и matrix, source commit и Actions run ID; policy дополнительно связывает release с Compatibility II GA JRE base.

`nl release publish-check` fail-closed повторно вычисляет certification и для 0.17.3 дополнительно требует policy suffixes `fabric-compatibility-II-0.17.1-stable-1.14-through-current-actual-client`, `quilt-compatibility-II-0.17.2-stable-1.14-through-current-actual-client` и `forge-modern-0.17.3-processor-based-1.13.2-through-current-actual-client` и `forge-legacy-0.17.4-real-1.12.2-universal-fmltweaker-actual-client` поверх всех Compatibility II GA policy gates. Target definition, matrix и certification включаются в release signature boundary. CI bundle без compatibility matrix может существовать как build candidate, но не проходит официальный publish-check.

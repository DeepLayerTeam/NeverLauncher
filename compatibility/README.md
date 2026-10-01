# Публичная CI Compatibility Matrix NeverLauncher

NeverLauncher 0.17.0 — **Minecraft Compatibility II GA**: Vanilla Compatibility Baseline II + Legacy Vanilla Java 8 + Java 16/17 + Java 21 + Java 25 + Cross-platform Vanilla + Actual Client E2E II + Compatibility Hardening + certified JRE binary base. Release compatibility формируется только из фактической Mojang materialization, package integrity, Compatibility Engine resolution, exact Java/JRE attestation и запуска настоящего Minecraft Java Client. Representative targets дополнительно обязаны пройти реальный join на официальный Mojang server той же версии.

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

Дополнительно обязательны Fabric, Quilt, Forge и NeoForge 1.21.1 на Java 21 с `scope=integration`. Для loader targets mutable `latest-stable` разрешается до выполнения target, а опубликованный result обязан содержать конкретную версию loader.

## Исполняемые scope

`client` предназначен для исторических Vanilla-версий, которые нельзя корректно проверять world-join на Paper 1.21.1. Для каждого такого target CI выполняет рабочий путь:

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

Для `>= 0.17.0` GA дополнительно требует минимум 45 обязательных Vanilla targets / 40 уникальных Vanilla releases и JRE attestation для каждого PASS: SHA-256 фактического `java`/`java.exe`, vendor, runtime version, VM, `java.home`, exact Java major и host OS/arch. `matrix.json` агрегирует concrete `jreBase`, а release certificate повторно связывает этот набор с target evidence.

Для product version `>= 0.16.2` сохраняется Baseline II. Начиная с `0.16.3`, агрегатор и CLI release certification fail-closed требуют десять Java 8 release-line targets 1.7.10–1.16.5. Для `>= 0.16.4` дополнительно обязательны pre-1.7 targets `1.0`, `1.1`, `1.2.5`, `1.3.2`, `1.4.7`, `1.5.2`, `1.6.4`, `1.7.10`. Для `>= 0.16.6` обязательна Java 16/17 линия `1.17.1`, `1.18.2`, `1.19.4`, `1.20.1`, `1.20.2`, `1.20.4`. Для `>= 0.16.7` дополнительно обязательна Java 21 линия `1.20.5`, `1.20.6`, `1.21`, `1.21.1`–`1.21.10`. Для `>= 0.16.8` обязательны Java 25 targets `26.1`, `26.1.1`, `26.1.2`, `26.3`; materializer и NeverRuntime независимо отклоняют отсутствующий или неверный `javaVersion.majorVersion`. Для `>= 0.16.9` `26.3` дополнительно обязателен на Linux/Windows/macOS x64+ARM64 с точным host-platform evidence и architecture-isolated natives. Для `>= 0.16.10` пять representative Linux/x64 Vanilla targets обязаны иметь `matchingServer=true` и доказанный join на verified Mojang server той же версии. Для `>= 0.16.11` release policy дополнительно фиксирует compatibility hardening, а repository gate требует resumable checksum-verified downloads, exact-version metadata recovery без stale aliases, quarantine/transactional natives и Managed Java executable integrity. Java coverage — `8/16/17/21/25`; все пять Vanilla/loader families и exact target binding обязательны. Удалить любую обязательную release-line или matching-server цель из `targets.json` и получить зелёный release невозможно.

Локальная проверка определения и агрегатора:

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

## Release certification

При сборке официального release CLI повторно валидирует `matrix.json` вместе с `compatibility/targets.json` и создаёт `COMPATIBILITY_CERTIFICATION.json`. Для 0.17.0 certification фиксирует required/passed targets, 45 Vanilla targets / 40 уникальных release IDs, пять mandatory matching-server pairs, Java majors, concrete certified JRE builds (vendor/runtime/SHA-256/OS/arch/target count), scopes, SHA-256 target definition и matrix, source commit и Actions run ID; policy дополнительно связывает release с Compatibility II GA JRE base.

`nl release publish-check` fail-closed повторно вычисляет certification и требует policy `all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact;legacy-vanilla-1.7.10-1.16.5-java8;legacy-vanilla-1.0-1.7.10-java8;vanilla-1.17.1-1.20.4-java16-17-exact;vanilla-1.20.5-1.21.10-java21-exact;vanilla-26.1.x-26.3-java25-exact;cross-platform-vanilla-windows-linux-macos-x64-arm64;actual-client-e2e-II-real-clients-matching-mojang-servers;compatibility-hardening-cache-recovery-upstream-failure-security;minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base`. Target definition, matrix и certification включаются в release signature boundary. CI bundle без compatibility matrix может существовать как build candidate, но не проходит официальный publish-check.

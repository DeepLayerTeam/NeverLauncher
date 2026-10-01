# Публичная CI Compatibility Matrix NeverLauncher

NeverLauncher 0.16.2 использует **Vanilla Compatibility Baseline II**: release compatibility формируется из фактической materialization и запуска настоящего Minecraft Java Client на нескольких поколениях Vanilla и на точной Java, а не из вручную выставленных PASS/FAIL. `compatibility/targets.json` содержит только обязательные цели; статусы появляются исключительно из CI evidence.

Обязательная Vanilla-линия 0.16.2:

| Minecraft | Java | scope |
| --- | ---: | --- |
| 1.7.10 | 8 | client |
| 1.12.2 | 8 | client |
| 1.16.5 | 8 | client |
| 1.17.1 | 16 | client |
| 1.18.2 | 17 | client |
| 1.20.4 | 17 | client |
| 1.20.6 | 21 | client |
| 1.21.1 | 21 | integration |

Дополнительно обязательны Fabric, Quilt, Forge и NeoForge 1.21.1 на Java 21 с `scope=integration`. Для loader targets mutable `latest-stable` разрешается до выполнения target, а опубликованный result обязан содержать конкретную версию loader.

## Исполняемые scope

`client` предназначен для исторических Vanilla-версий, которые нельзя корректно проверять world-join на Paper 1.21.1. Для каждого такого target CI выполняет рабочий путь:

```text
official Mojang version metadata
 -> materialize client.jar/libraries/assets/natives
 -> local SHA-256 package verify
 -> resolve Compatibility Engine metadata
 -> verify exact target Java major
 -> launch real Minecraft main class under Xvfb
 -> require process to stay healthy until certification window or exit successfully
 -> store runtime log + machine-verifiable evidence
```

Это не metadata-only gate: `neverruntime certify-vanilla` запускает фактический материализованный клиент. Для legacy metadata без `arguments.jvm` Compatibility Engine добавляет launcher JVM baseline (`java.library.path`, launcher identity и classpath), поэтому 1.7.10/1.12.2 проходят тем же runtime resolver, а не отдельной заглушкой.

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

Для product version `>= 0.16.2` агрегатор и CLI release certification fail-closed требуют все восемь Vanilla anchors, Java coverage `8/16/17/21`, все пять loader families и exact target binding. Удалить старую Vanilla-ветку из `targets.json` и получить зелёный release невозможно.

Локальная проверка определения и агрегатора:

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

## Release certification

При сборке официального release CLI повторно валидирует `matrix.json` вместе с `compatibility/targets.json` и создаёт `COMPATIBILITY_CERTIFICATION.json`. Для 0.16.2 certification фиксирует required/passed targets, восемь Vanilla versions, Java majors, scopes, SHA-256 исходной target definition и агрегированной matrix, source commit и Actions run ID.

`nl release publish-check` fail-closed повторно вычисляет certification и требует policy `all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact`. Target definition, matrix и certification включаются в release signature boundary. CI bundle без compatibility matrix может существовать как build candidate, но не проходит официальный publish-check.

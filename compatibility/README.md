# Публичная CI Compatibility Matrix NeverLauncher

Матрица совместимости NeverLauncher формируется только из фактических запусков настоящего Minecraft Java Client. Файл `targets.json` содержит цели проверки, но **не содержит статусов PASS/FAIL**.

Канонические цели текущего compatibility release:

- Vanilla 1.21.1 — Linux x86_64;
- Fabric 1.21.1 — Linux x86_64, concrete loader разрешается из `latest-stable` до публикации release;
- Quilt 1.21.1 — Linux x86_64;
- Forge 1.21.1 — Linux x86_64;
- NeoForge 1.21.1 — Linux x86_64.

Каждый target проходит один и тот же проверяемый путь:

```text
upstream metadata / installer
 -> materialization
 -> local SHA-256 package verify
 -> canonical /api/v1 upload
 -> Ed25519 signed immutable release
 -> clean NeverRuntime sync
 -> pinned signature + file integrity verification
 -> Xvfb actual Minecraft client
 -> Paper 1.21.1 world join
 -> launcher session revoke
 -> subsequent join denied
```

Workflow `.github/workflows/compatibility.yml` запускается после push в `main`, по расписанию и вручную. Каждый target публикует machine-verifiable `compatibility-result.json`. Финальный job скачивает результаты, проверяет соответствие exact commit/run ID, целевой версии Minecraft/loader/OS/arch, concrete loader version и обязательным evidence checks, после чего генерирует `matrix.json` и `matrix.md` в GitHub Actions Summary и artifact.

Ручная запись зелёного статуса в `targets.json` запрещена repository policy. Пропущенный target, дублированный result, mutable `latest-stable` в уже опубликованном loader result, несовпадение commit/run ID или отсутствие actual-client evidence переводят итоговую матрицу в failed.

Локальная проверка определения и агрегатора:

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

## Release certification

Minecraft Compatibility Release сохраняет состав обязательных target'ов и добавляет связь между CI evidence и production release bundle. Стабилизация materialization из `0.10.7` остаётся обязательной частью контура:

- materializer одного `clientDir` сериализован exclusive lock-файлом;
- transient upstream `408/425/429/5xx` повторяются ограниченное число раз;
- symlink-компоненты client tree и symlink package artifacts запрещены;
- generated `natives/<os>` пересобираются с нуля;
- Forge/NeoForge processor scratch data очищается перед каждым install;
- агрегатор требует `exitCode == 0`, `paperHealthy == true`, совпадение `manifestLoader` и полный набор обязательных evidence files.

Таким образом `status: passed` в одном JSON недостаточен для зелёной публичной матрицы: результат должен пройти независимую агрегационную проверку.

## Как матрица становится частью release

Агрегированный `matrix.json` сам по себе не является release trust anchor. При сборке официального release CLI повторно валидирует его вместе с `compatibility/targets.json` и создаёт `COMPATIBILITY_CERTIFICATION.json`. Проверяются exact `productVersion`, source commit, Actions run ID, отсутствие matrix errors, все required targets, concrete loader versions, `exitCode=0` и полный набор mandatory checks.

В release bundle сохраняются точные копии target definition и matrix. Certification содержит их SHA-256, commit/run ID и списки required/passed targets. `nl release publish-check` для Minecraft Compatibility Release и новее fail-closed требует эти три файла и повторно вычисляет certification перед разрешением публикации. Они включаются в `SHA256SUMS` и покрываются Ed25519-подписью release bundle.

CI bundle без переданного `NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE` допустим только как build candidate; он проходит cryptographic `release verify`, но не проходит `release publish-check`.

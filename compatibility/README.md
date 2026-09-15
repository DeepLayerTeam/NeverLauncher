# Публичная CI Compatibility Matrix NeverLauncher 0.10.6

Матрица совместимости NeverLauncher формируется только из фактических запусков настоящего Minecraft Java Client. Файл `targets.json` содержит цели проверки, но **не содержит статусов PASS/FAIL**.

Канонические цели `0.10.6`:

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

# Client Factory / MirrorHelper: рабочий workspace (0.40.5)

`nl runtime client-factory apply-workspace` выполняет загрузку Minecraft, разрешение и установку клиентских файлов, дополнительный импорт `.mrpack`/CurseForge, установку указанных модов и Maven JAR, регистрацию библиотек в version profile, проверенную трансформацию authlib и настройку совместимости JVM. Результат появляется в `--client-dir` **только после** всех проверок целостности. Существующий каталог не перезаписывается.

Пример `workspace.json`:

```json
{
  "schemaVersion": "launcher.mirror-workspace.v1",
  "minecraft": "1.20.1",
  "loader": "fabric",
  "loaderVersion": "0.16.9",
  "modpack": "pack.mrpack",
  "mods": [
    {"path": "mods/local-addition.jar", "file": "files/local-addition.jar", "sha256": "<actual SHA-256 of the JAR>"}
  ],
  "libraries": [
    {"coordinate": "example:compatibility-library:1.0", "file": "files/compatibility-library.jar", "sha256": "<actual SHA-256 of the JAR>"}
  ],
  "compatibility": "compatibility.json"
}
```

Поля `modpack`, `mods`, `libraries`, `compatibility` и `authlibPatches` необязательны. Если указан `modpack`, Minecraft, loader и loaderVersion в его manifest обязаны точно совпадать с workspace. При несовпадении выполнение останавливается до установки. Пути локальных файлов разрешаются относительно `workspace.json`, а байты сверяются с SHA-256.

Пример вызова:

```sh
nl runtime client-factory apply-workspace \
  --file ./workspace/workspace.json \
  --client-dir ./output/client-1 \
  --target linux/x64 \
  --shared-cache-dir ./cache \
  --output ./output/factory-result.json
nl runtime client-factory verify --client-dir ./output/client-1
```

Для CurseForge-модпаков с требуемыми записями файлов нужен официальный API-ключ (`NEVERLAUNCHER_CURSEFORGE_API_KEY` или `--curseforge-api-key`). Для локального файла, отсутствующего на разрешённом CDN, используйте `--manual-dir`; файл всё равно должен пройти проверку по ожидаемым исходным хешам. CurseForge-паки только с ZIP overrides не требуют API-ключа. Для публикации собранного модпака другим пользователям используйте разрешительный список источников `--permissions-file` вместе с `--distribution redistributable`.

`compatibility.json` — обычный проверяемый `launcher.authlib-classloader.v1` запрос; загрузка стороннего Yggdrasil Java agent допускается **только** с `--allow-auth-agent true`. Подписанные или неподходящие JAR отклоняются. При необходимости трансформации authlib используйте в workspace:

```json
"authlibPatches": [
  {
    "target": "libraries/com/mojang/authlib/4.0/authlib-4.0.jar",
    "patch": "files/authlib-overlay.jar",
    "baseSha256": "<actual original JAR SHA-256>",
    "patchSha256": "<actual overlay JAR SHA-256>",
    "expectedSha256": "<actual result JAR SHA-256>"
  }
]
```

Для Forge/NeoForge можно указать `--installer-file`, `--installer-sha256`, `--installer-url`, `--java`, `--processor-timeout`, `--processor-sandbox`; для метаданных версий — `--maven-metadata-url`. Параметры разрешения версии и URL доступны также для детерминированного локального тестового HTTP-репозитория. Это не отменяет обязательной проверки настоящего запуска Minecraft на целевой ОС и Java: тесты на локальных артефактах не подтверждают работу всех upstream-версий.

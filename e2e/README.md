# Production E2E NeverLauncher 0.10.5

Production E2E запускается командой:

```bash
e2e/scripts/run-minecraft-e2e.sh
```

`0.10.5` использует настоящий Minecraft Java Client, а не Java fixture как основной release gate. Сценарий:

1. поднимает PostgreSQL/Redis, production-configured API, Velocity 3.4.0, Paper 1.21.1 и Purpur 1.21.1;
2. применяет реальные миграции и регистрирует ServerBridge nodes;
3. через `nl runtime vanilla-package` получает Minecraft 1.21.1 из официальных Mojang metadata, проверяет client/libraries/assets/natives/logging и формирует Never package;
4. локально выполняет полный `nl client verify`;
5. загружает все файлы package через канонический `/api/v1`, публикует подписанный immutable release и заново скачивает его в чистый client root через NeverRuntime;
6. NeverRuntime проверяет pinned Ed25519 signature и SHA-256 каждого release artifact;
7. запускает настоящий Minecraft client под `Xvfb` с software rendering и `--quickPlayMultiplayer 127.0.0.1:25571`;
8. gate требует фактические ServerBridge allow-события и строку Paper `E2EPlayer joined the game`;
9. после отзыва launcher session проверяет deny; Velocity/Purpur сохраняют отдельное protocol-level покрытие bridge allow/revoke/deny.

`e2e/scripts/publish-client-package.py` не является mock uploader: он повторно SHA-256-хеширует каждый materialized artifact перед multipart upload и сверяет checksum/size, возвращённые Backend API.

Канонический Compose-файл: `e2e/docker-compose.minecraft-e2e.yml`. Runtime-файлы и evidence создаются в `e2e/runtime/` и не являются исходниками репозитория.

Для локального запуска нужны Docker, Go, Rust/Cargo, JDK 21, Gradle, `curl`, `jq`, Python 3, `xvfb-run` и системные OpenGL/X11 библиотеки. Нужен сетевой доступ к официальным Mojang endpoints и registry/репозиториям, используемым build pipeline.

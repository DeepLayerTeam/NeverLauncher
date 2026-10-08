# Рабочий E2E NeverLauncher

## Доверие к устройству миграция + PostgreSQL E2E (`0.12.10`)

Перед полным Доверие к устройству жизненный цикл выполняется точный-обновление `0.12.9 → 0.12.10`:

```bash
bash e2e/scripts/run-device-trust-migration-e2e.sh
bash e2e/scripts/run-device-trust-e2e.sh
```

Первый сценарий создаёт схема строго из миграция `0001..0017`, сеет допустимые устаревший состояния, доказывает старый PostgreSQL запрещать для `key-rotate`, затем применяет поставка CLI миграция `0018` и проверяет новые ownership/lifecycle ограничения. Второй сценарий требует созданное миграция свидетельство и только после этого выполняет полный Доверие к устройству жизненный цикл.

Сценарий поднимает рабочий-настраивать Серверная часть, PostgreSQL и Redis через `docker-compose.federation-e2e.yml`, явно применяет и проверяет миграция и выполняет реальные Ed25519/P-256 подписи. Проверяются регистрация повторное воспроизведение запрещать, `binding_epoch`, подписанный обновление, dual-доказательство ротация, метка удаления старого отпечаток, ServerBridge запрещать после замена, сохранённый риск step-up, запрос-ответ аттестация + повторное воспроизведение запрещать, запрещать восстановление без устойчивый к фишингу step-up, реальная WebAuthn P-256 registration/assertion процедура, успешный ключ восстановление и отзыв каскад.

Публикуемые жизненный цикл свидетельство находятся в `e2e/device-trust-result/`, а точный-обновление свидетельство — в `e2e/device-trust-migration-result/`. Закрытый ключи и среда выполнения учётные данные живут в `e2e/device-trust-runtime/` и не являются свидетельство; перед PASS скрипт отказ с блокировкой проверяет готовый к публикации каталог на access/refresh/private-key материал. Публичная матрица собирается `.github/workflows/device-trust.yml` только из exact-commit/run результаты.

Для локального протокол E2E нужны Docker/Compose, Go, `psql`, `curl`, `jq`, Python 3 и OpenSSL. Строгий релиз предварительная проверка включает этот сценарий автоматически; вручную: `NEVERLAUNCHER_PREFLIGHT_DEVICE_TRUST_E2E=1./scripts/release/preflight.sh`.

Основной рабочий E2E запускается командой:

```bash
e2e/scripts/run-minecraft-e2e.sh
```

Рабочий E2E использует настоящий Minecraft Java Клиент, а не Java фикстура. Один и тот же скрипт поддерживает два режима.

### Полный рабочий режим

По умолчанию `NEVERLAUNCHER_E2E_MODE=full`: поднимаются PostgreSQL/Redis, рабочий-настраивать API, Velocity 3.4.0, Paper 1.21.1 и Purpur 1.21.1. Vanilla 1.21.1 проходит материализация, локальную SHA-256 проверку, загрузка через `/api/v1`, Ed25519 публикация, чистый NeverRuntime синхронизация, реальный запуск под Xvfb и фактический вход на Paper. После отзыв проверяется запрещать; Velocity/Purpur дополнительно проходят протокол-уровень allow/revoke/deny.

### Совместимость режим

Публичная матрица вызывает `e2e/scripts/run-compatibility-case.sh`. Обёртка переводит основной скрипт в `NEVERLAUNCHER_E2E_MODE=compatibility`, запускает только обязательный Paper узел и выбирает загрузчик через переменные:

```text
NEVERLAUNCHER_E2E_MINECRAFT_VERSION
NEVERLAUNCHER_E2E_LOADER=vanilla|fabric|quilt|forge|neoforge
NEVERLAUNCHER_E2E_LOADER_VERSION=<selector>
NEVERLAUNCHER_COMPAT_TARGET_ID=<canonical target id>
```

Для Fabric/Quilt/Forge/NeoForge используется соответствующий рабочий `nl runtime <loader>-package`; изменяемый селектор разрешается materializer-ом до конкретный загрузчик версия. Начиная с 0.17.8 интеграционный якорь дополнительно запускает `run-loader-native-e2e.sh`: чистый выделенный сервер того же загрузчик получает точный `resolvedLoaderVersion`, серверные загрузчик артефакты проверяются на диске, после чего фактический материализовать клиент через NeverRuntime подключается напрямую к `127.0.0.1:25580`. PASS требует работоспособный сервер и реальный `NeverLauncherCertification joined the game` в сервер журнал; одного открытого порта или клиент тайм-аут недостаточно.
Начиная с 0.17.9 клиент сертификация для текущий Fabric/Quilt/Forge/NeoForge якоря выполняется на Windows/Linux/macOS x64/ARM64. Загрузчик исполнитель больше не требует Linux x64: Linux использует Xvfb, Windows/macOS запускают NeverRuntime нативно, а `loader-platform.json` связывает материализатор цель, фактически выбранный `nativesDirectory`, количество native-файлов и `nativeTreeSha256`. Несовпадение OS/arch нативный дерево блокирует PASS.


После этого все загрузчик семейство сохраняют существующую доверие граница:

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

Для Vanilla цели с `matchingServer=true` обёртка вместо тайм-аут-только сертификация вызывает `run-vanilla-matching-e2e.sh`. Сценарий материализует проверен Mojang клиент и `downloads.server` из одной точный `version.json`, проверяет сервер JAR по объявлять SHA-1/size, запускает сервер на цель Java, затем запускает NeverRuntime с `--server 127.0.0.1 --server-port <ephemeral>`. PASS возможен только если сервер остаётся работоспособный и его журнал подтверждает вход `NeverLauncherCertification`. В 0.16.10 это обязательно для 1.7.10/Java 8, 1.17.1/Java 16, 1.20.4/Java 17, 1.21.10/Java 21 и 26.3/Java 25.

`run-compatibility-case.sh` формирует `e2e/compatibility-result/compatibility-result.json`. Для loader/integration PASS требует пакет проверка, действительный манифест подпись, чистый синхронизация, реальный клиент запускать, Paper подключение, revoke/deny и работоспособный Paper свидетельство. Для соответствовать Vanilla PASS вместо этого требует `matchingServer`, `serverVersionMatched`, `serverHealthy` и `clientJoinedServer`, а также `vanilla-server-install.json`, `matching-server.json` и сервер журнал. Результат содержит точный Git фиксация и GitHub Действия запуск ID; агрегатор не принимает результат от другого запуска.

`e2e/scripts/publish-client-package.py` повторно SHA-256-хеширует каждый материализовать артефакт перед multipart загрузка, сверяет checksum/size из Серверная часть и отклоняет обход путей и symlink-компоненты внутри клиент дерево.

Канонический Compose-файл: `e2e/docker-compose.minecraft-e2e.yml`. Runtime/evidence создаются в `e2e/runtime/` и `e2e/compatibility-result/`, оба каталога исключены из исходник дерево.

Для локального запуска нужны Docker, Go, Rust/Cargo, JDK 21, Gradle, `curl`, `jq`, Python 3, `xvfb-run` и системные OpenGL/X11 библиотеки. Нужен сетевой доступ к Mojang, Fabric/Quilt Мета, Forge/NeoForge Maven и реестр/репозиториям конвейер сборки.
## Federation/PostgreSQL Аутентификация Федерация E2E (`0.12.0`)

Для auth/federation контроль выпуска используется отдельный сценарий:

```bash
bash e2e/scripts/run-federation-postgres-e2e.sh
```

Он поднимает PostgreSQL, Redis и три Серверная часть экземпляр (`api-a`, `api-b`, `api-c`), применяет и проверяет миграция каталог, выполняет вход на, перезапускает, делает обновление через разные экземпляры, воспроизводит старый токен обновления и требует, чтобы compromise/revoke был виден всем трём Серверная часть. Сценарий требует Docker/Compose, `psql`, `curl`, `jq`, Go и Python.

Быстрый connector/failure контроль без Docker:

```bash
python3 scripts/test/federation-e2e.py
```

Строгий релиз предварительная проверка включает PostgreSQL сценарий автоматически; вручную это можно включить через `NEVERLAUNCHER_PREFLIGHT_FEDERATION_POSTGRES=1`.



## ServerBridge Без патчей Предоставление учётной записи (0.19.9)

- `nl server-bridge detect --server-root <dir>` — определить сертифицированный платформа без изменения файлов.
- `nl server-bridge install --server-root <dir> --artifact-dir <release>` — выбрать/проверить платформа артефакт, установить мост, создать конфигурация, Ed25519 узел идентичность и публичный-только регистрация запрос.
- `nl server-bridge enroll --server-root <dir> --backend <url> --token <admin-token>` — зарегистрировать узел идентичность; `--rotate` использует существующий ротировать-идентичность API.
- `nl server-bridge status --server-root <dir> [--backend <url> --token <token>]` — проверить локальный artifact/hash/identity и, при наличии учётные данные, Серверная часть узел.
- `nl server-bridge upgrade...` — транзакционно заменить мост артефакт без ротации узел идентичность.
- `nl server-bridge rollback --server-root <dir> [--transaction <id>]` — восстановить предыдущие управляемый файлы. Все изменяющий команды поддерживают `--dry-run` там, где применимо.

Рабочий предоставление учётной записи требует sibling `SERVERBRIDGE3_CERTIFICATION.json` или точная версия `BRIDGE_RELEASE_ALLOWLIST.json`; `--allow-unverified-artifact` предназначен только для разработка. Универсальный предоставление учётной записи не патчит authlib/core и отказ с блокировкой отклоняет Mohist/Arclight/Magma/CatServer/Banner/Cardboard без отдельной сертификация матрица.

# NeverLauncher CLI

## Загрузчик Разрешение и Закрепление — 0.17.7

Все рабочий загрузчик материализатор поддерживают `--resolution-lock <path>`. Первый запуск разрешает изменяемый селектор в конкретный загрузчик версия и атомарно пишет блокировка с разрешение-исходник SHA-256, payload/profile SHA-256, runtime-profile/materialized-files SHA-256 и общей `reproducibilitySha256`. Повторный запуск читает блокировка до изменяемый разрешение, повторно скачивает только закреплённый конкретный полезная нагрузка и отказ с блокировкой сравнивает его и итоговый среда выполнения профиль с блокировка.

Пример: `nl runtime fabric-package --minecraft 1.21.1 --loader-version latest-stable --resolution-lock.neverlauncher/fabric.lock.json...`. Тот же механизм работает для Quilt, Forge и NeoForge; CI выполняет повторное воспроизведение и публикует сырой блокировка как релиз свидетельство.

## NeoForge Совместимость II — 0.17.6

`nl runtime neoforge-install` / `neoforge-package` исполняют рабочий NeoForge обработчик установщик для stable-линии Minecraft 1.20.1–26.2. Разрешатель отдельно поддерживает официальный 1.20.1 артефакт `net.neoforged:forge` и современный `net.neoforged:neoforge`, проверяет соответствие загрузчик↔Minecraft, выполняет клиент обработчики на цель Java и возвращает только конкретный неизменяемый загрузчик версия.

## Forge Устаревший 1.7.10 — 0.17.5

`nl runtime forge-install` / `forge-package` теперь исполняют Forge 1.7.10 V1 универсальный установщик как отдельный LaunchWrapper/FML путь. Материализатор требует Java 8, `net.minecraft.launchwrapper.Launch` и `cpw.mods.fml.common.launcher.FMLTweaker`, нормализует устаревший профиль к Vanilla 1.7.10 при отсутствии `inheritsFrom`, проверяет универсальный JAR и фиксирует `legacyTweaker`, `legacyBaseVersion`, `legacyProfileNormalized` и неизменяемый Forge версия в установка свидетельство.

## Forge Устаревший 1.12.2 — 0.17.4

`nl runtime forge-install` / `forge-package` теперь исполняют реальный Forge 1.12.2 устаревший установщик. V1 установщик извлекает универсальный JAR из `install.filePath`, проверяет SHA-1, сохраняет вложенный `versionInfo` и материализует только клиент-обязательный библиотеки; repacked 1.12.2 установщик с пустыми обработчики использует встроенный Maven универсальный артефакт. Результат фиксирует `installMode`, универсальный SHA-1/SHA-256 и конкретный Forge версия для сертификация релиза.

`nl` — операционный CLI для канонического NeverLauncher API `/api/v1`. Исторические RC/stable/platform/product/extension/beta состояние-только семейства команд удалены.

Все общие отчёты CLI, ранее помеченные историческими `schemaVersion` 4.x–8.x, используют единую версию схемы `1.0`. Специализированные форматы, например manifest/runtime схема, сохраняют собственные версии формата.

## Основные команды

```bash
nl version
nl manifest ...
nl update ...
nl runtime ...
nl loader ...
nl project ...
nl diagnostics ...
```

## Minecraft среда выполнения материализация

Рабочие materializer-команды:

```bash
nl runtime vanilla-package --minecraft 1.21.1 --client-dir .neverlauncher/vanilla/1.21.1 --output client-package.json
nl runtime fabric-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/fabric/1.21.1 --output client-package.json
nl runtime quilt-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/quilt/1.21.1 --output client-package.json
nl runtime forge-package --minecraft 1.20.1 --loader-version latest-stable --client-dir .neverlauncher/forge/1.20.1 --output client-package.json
nl runtime neoforge-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/neoforge/1.21.1 --output client-package.json
```

Fabric использует официальный Мета API v2, Quilt — Мета API v3. Forge и NeoForge загружают проверенный официальный Maven установщик JAR, выполняют клиент обработчики из `install_profile.json`, проверяют выходные данные и нормализуют дочерний `version.json`. До упаковки изменяемый псевдоним `latest-stable` разрешается в конкретный загрузчик версия и фиксируется разрешение блокировка. Повторное воспроизведение обязан воспроизвести source/payload/runtime-profile/materialized-files SHA-256; обычный пакет SHA-256 + подписанный манифест жизненный цикл NeverLauncher остаётся отдельным уровнем целостность.

## Операции Серверная часть

```bash
nl auth login --backend https://launcher.example
nl auth sessions --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl admin overview --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl install readiness --backend https://launcher.example
nl operations diagnostics --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl backup status --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
```

Первичная инициализация администратора использует одноразовый bootstrap-заголовок:

```bash
nl install bootstrap-admin \
  --backend https://launcher.example \
  --bootstrap-token "$NEVERLAUNCHER_BOOTSTRAP_TOKEN" \
  --email admin@example.test \
  --password '...'
```

## Единый Транзакционный Обновлятор Ядро

```bash
nl update plan --from old.json --to new.json
nl update apply --from old.json --to new.json --source-root ./payload --root ./install
nl update status --root ./install
nl update recover --root ./install
nl update self-test
```

Для `0.15.7+` Настольное приложение self-обновление использует внешний `nl update components` вспомогательный модуль: рабочий пакет обязан иметь закреплённый SHA-256 и платформа компонент манифест, NeverGuard останавливается до переключение, а Desktop/Guard/Runtime применяются одной откат-граница; macOS обновляет целый нотариально заверенный `.app`.

Для `0.15.6+` `client install/update/repair/rollback/package-apply` используют один транзакционный движок: проверен подготовка на том же файловая система, долговременный журнал, резервное копирование только touched пути, атомарный заменять, post-проверять и автоматический сбой откат. Управление состояние находится в `.neverlauncher/updater`; полезная нагрузка не может изменять этот каталог, проходить через символическая ссылка или выходить за установка корень.

## Релизы и пакеты

```bash
nl release doctor
VERSION="$(cat VERSION)"
nl release build --out "dist/release-${VERSION}" \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --compatibility-matrix /path/to/matrix.json \
  --compatibility-targets compatibility/targets.json \
  --guard-ci-matrix /path/to/guard-matrix.json \
  --guard-ci-targets guard-ci/targets.json \
  --source-commit "$(git rev-parse HEAD)"
nl release sign dist/release-${VERSION} --private-key /secure/release-private.pem
nl release verify dist/release-${VERSION} --public-key /etc/neverlauncher/root-public.pem \
  --trust-state /var/lib/neverlauncher/release-trust-state.json \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json
nl release publish-check dist/release-${VERSION} --public-key /etc/neverlauncher/root-public.pem \
  --trust-state /var/lib/neverlauncher/release-trust-state.json \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json
nl delivery verify-windows --bundle dist/release-${VERSION} --version "${VERSION}" --production
nl delivery verify-public-matrix --bundle dist/release-${VERSION} --version "${VERSION}"
nl delivery public-e2e --matrix-url "https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v${VERSION}/PUBLIC_PRODUCTION_DELIVERY_MATRIX.json" \
  --public-key /etc/neverlauncher/root-public.pem --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/public-e2e-trust-state.json
nl packaging prepare
nl packaging verify
```


Для `0.15.2+` Windows публикация дополнительно требует две канонические архитектуры (`windows-x64`, `windows-arm64`) и рабочий `WINDOWS_SIGNING_EVIDENCE.json`. `release publish-check` повторно связывает подписанные PE/ZIP/пакет манифесты с `DELIVERY_MANIFEST.json`; неподписанный CI кандидат публикацией не считается.

Для `0.13.9+` готовый к публикации комплект требует точный-фиксация Защита CI свидетельство для Linux/Windows/macOS. `scripts/release/build-release.sh` получает пути через `NEVERLAUNCHER_GUARD_CI_MATRIX_FILE`, `NEVERLAUNCHER_GUARD_CI_TARGETS_FILE` и `NEVERLAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR`; CLI повторно проверяет точный платформа артефакт хеширует при `release build` и `release publish-check`.

В `0.13.10` каждый Защита цель результат также обязан совпадать по `repository`; свидетельство из другого ответвление отклоняется даже при совпавших commit/run. Перед рабочий развёртывание с 0.13.9 выполните `nl db migrate apply` и `nl db migrate verify`: последний миграция должна быть `0020_guard_migration_compatibility_stabilization_01310`. Для 0.14.2 последний миграция — `0022_serverbridge_crypto_node_identities_0142`: общий ServerBridge bearer учётные данные удалены, публичный Ed25519 узел идентичности и повторное воспроизведение одноразовые значения стали PostgreSQL состояние; существующие 0.14.1 узлы требуют `rotate-identity` регистрация. Для 0.14.3 последний миграция — `0023_one_time_join_tickets_0143`: активные устаревший подключение авторизация сбрасываются на граница безопасности, новые ServerBridge билеты привязываются к точный узел идентичность epoch/fingerprint и атомарно consume-ятся с использование доказательство; Yggdrasil `/hasJoined` также одноразовое использование.

Для обращений к Серверная часть используйте `--backend`, а для защищённых маршрутов `/api/v1` — `--token` или `NEVERLAUNCHER_TOKEN`.

## Production-операции без состояние-только заглушек

```bash
nl pipeline stage --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --package-id <id>
nl pipeline smoke-test --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --package-id <id>
nl pipeline publish --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --package-id <id>
nl storage consistency --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl storage audit --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl migrate apply --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl migrate rollback --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --backup-id <id> --confirm <id>
nl install storage-check --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl install verify --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
```

`0.15.8+` `release verify` и `security verify-signature` требуют внешний автономный-корень Ed25519 открытый ключ и постоянный доверие состояние. Корень ключ из комплект не принимается; release-ключ подписи принимается только через подписанный корневым ключом `RELEASE_TRUST_POLICY.json`.

`0.15.9+` `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json` обязан покрывать Windows/Linux/macOS x64+ARM64 и конкретный пакет/JRE/компонент байты. `delivery public-e2e` предназначен для после публикации проверки реальных публичных URL и повторно запускает Релиз Проверка v2 над скачанным комплект.

## P3.2v4: реальный client/desktop/key жизненный цикл

Клиент жизненный цикл использует уже собранный `client-package.json` и хранилище с тем же структура:

```bash
nl client install --package dist/client-package.json --storage-dir ./storage --client-dir ./minecraft
nl client verify --package dist/client-package.json --client-dir ./minecraft
nl client repair --package dist/client-package.json --storage-dir ./storage --client-dir ./minecraft
nl client cleanup --package dist/client-package.json --client-dir ./minecraft
nl client rollback --client-dir ./minecraft --target previous
```

`cleanup` не удаляет неизвестные файлы безвозвратно: управляемые orphan-файлы перемещаются в `.neverlauncher/quarantine`. Перед install/update/repair создаётся откат снимок.

Автономный первый запуск не зависит от исходного checkout и требует неизменяемый образ ссылки:

```bash
nl install first-run --output-dir ./neverlauncher-production \
  --api-image registry.example/neverlauncher-api@sha256:<digest> \
  --admin-image registry.example/neverlauncher-admin@sha256:<digest>
```

Настольное приложение package/verify работает только с реально собранными артефакты:

```bash
nl desktop package --artifact-dir dist/release-${VERSION} --out dist/desktop-package --platform linux
nl desktop verify dist/desktop-package
```

Ключ жизненный цикл и supply-цепочка:

```bash
nl security rotate-key --registry-dir /secure/neverlauncher-keys --key release-signing
nl security keys --registry-dir /secure/neverlauncher-keys
nl security revocation-list --registry-dir /secure/neverlauncher-keys --revoke <keyId>
nl security attest --path PROVENANCE.json --private-key /secure/.../private.pem
nl security sbom --source-root . --output SBOM.spdx.json
nl security provenance --source-root . --artifact-dir dist/release-${VERSION} --output PROVENANCE.json
```

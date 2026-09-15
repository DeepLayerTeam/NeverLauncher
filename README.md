# NeverLauncher 0.10.3

NeverLauncher — self-hosted LauncherOps-платформа для Minecraft-проектов. Версия `0.10.3` добавляет рабочую production-материализацию **Fabric + Quilt** поверх проверенного Vanilla-клиента: CLI выбирает совместимую версию загрузчика через официальный Meta API, получает client profile, проверенно скачивает Maven-зависимости и превращает результат в обычный подписываемый immutable Never release.

## Рабочий контур

```text
Mojang metadata -> Vanilla materializer -> проверенное Vanilla tree
Fabric/Quilt Meta API -> pinned loader profile -> проверенные Maven libraries
                    -> SHA-256 package/release -> подписанный immutable manifest
                    -> Compatibility Engine -> Managed Java -> JVM
```

Сохраняется весь контур `0.10.2`: Compatibility Engine, Managed Java, Vanilla materializer, signed metadata trust boundary, immutable published releases, verify/repair/rollback, Ed25519 key lifecycle, SBOM/provenance, Backend API, Desktop и ServerBridge.

## Managed Java 0.10.3

NeverRuntime больше не требует заранее установленную подходящую Java. Перед построением/выполнением launch plan он:

1. получает требуемую major-версию из signed manifest и Mojang `javaVersion.majorVersion`;
2. отклоняет конфликт между manifest и Mojang metadata;
3. принимает custom Java только если профиль разрешает `allowCustomPath` и версия совпадает;
4. для `distribution=system` требует подходящую системную Java;
5. для `temurin`/`any` использует подходящую системную JVM либо устанавливает Temurin JRE через Adoptium API;
6. проверяет platform, размер и SHA-256 архива, скачивает через HTTPS во временный файл, безопасно распаковывает в staging и атомарно публикует runtime;
7. после установки повторно выполняет `java -version` и принимает только требуемую major-версию;
8. повторные запуски используют проверенный локальный runtime cache.

Поддерживаемые managed major-версии в `0.10.3`: Java 8, 17, 21 и 25.

Ручная установка/проверка Managed Java:

```bash
neverruntime java ensure --major 21 --distribution temurin
```

Desktop использует тот же NeverRuntime installer; установка Java не дублируется в JavaScript/Tauri UI.

## Vanilla materializer 0.10.3

`nl runtime vanilla-install` выполняет реальную материализацию Vanilla client tree из `version_manifest_v2.json`:

- проверяет SHA-1 Mojang version metadata;
- загружает и проверяет client JAR;
- разрешает libraries и OS/architecture rules;
- загружает native classifiers для выбранных target-платформ и безопасно извлекает native-файлы;
- загружает asset index и все asset objects с проверкой SHA-1/size;
- поддерживает legacy `virtual`/`map_to_resources` assets;
- загружает `logging.client.file`;
- сохраняет детерминированное локальное состояние и повторно использует только файлы, прошедшие проверку.

Пример:

```bash
nl runtime vanilla-install \
  --minecraft latest-release \
  --client-dir .neverlauncher/vanilla/latest \
  --target windows/x86_64
```

Команда `vanilla-package` сразу превращает материализованное дерево в стандартный Never client package с SHA-256 каждого файла и готовыми `manifestSettings` для Compatibility Engine:

```bash
nl runtime vanilla-package \
  --minecraft 1.21.1 \
  --client-dir .neverlauncher/vanilla/1.21.1 \
  --project my-project \
  --profile vanilla \
  --channel stable \
  --output client-package.json
```

После загрузки файлов в обычный Never release опубликованный manifest остаётся immutable и запускается через `classpathStrategy=compatibility`. Upstream SHA-1 используется только для проверки официальных Mojang artifacts при материализации; внутри Never release файлы фиксируются существующим SHA-256 lifecycle.

## Fabric + Quilt 0.10.3

`nl runtime fabric-install` и `nl runtime quilt-install` работают поверх того же проверенного Vanilla tree. Materializer:

1. разрешает фактическую Minecraft-версию через Mojang manifest;
2. запрашивает список совместимых loader versions из официального Fabric Meta v2 или Quilt Meta v3;
3. фиксирует конкретную stable loader version вместо mutable `latest`;
4. получает официальный `profile/json` для выбранной пары Minecraft/loader;
5. проверяет `inheritsFrom`, `mainClass` и наличие выбранного loader artifact;
6. для каждой Maven-библиотеки получает `.sha1`, проверяет JAR и записывает точные `url/path/sha1/size` в локальный version profile;
7. сохраняет дочерний profile в `versions/<profile>/<profile>.json` и включает его вместе со всеми loader libraries в обычный SHA-256 Never package;
8. NeverRuntime затем разрешает этот profile через реальный `inheritsFrom` Compatibility Engine и допускает только paths из подписанного release manifest.

Пример Fabric:

```bash
nl runtime fabric-package \
  --minecraft 1.21.1 \
  --loader-version latest-stable \
  --client-dir .neverlauncher/fabric/1.21.1 \
  --project my-project \
  --profile fabric \
  --channel stable \
  --output client-package.json
```

Пример Quilt:

```bash
nl runtime quilt-package \
  --minecraft 1.21.1 \
  --loader-version latest-stable \
  --client-dir .neverlauncher/quilt/1.21.1 \
  --project my-project \
  --profile quilt \
  --channel stable \
  --output client-package.json
```

Для production внешние Meta/Maven URL обязаны использовать HTTPS. HTTP допускается только для loopback fixture-тестов. Если Maven repository не предоставляет корректный SHA-1 sidecar, strict materialization завершается ошибкой вместо публикации непроверенной зависимости.

## Compatibility Engine

При `runtime.launch.classpathStrategy = "compatibility"` NeverRuntime читает подписанный `version.json`, разрешает `inheritsFrom`, Mojang rules, ordered classpath, native classifiers, JVM/game arguments и logging config. Для materialized Vanilla natives автоматически выбирается текущий каталог `natives/windows`, `natives/linux` или `natives/osx`.

Каждый metadata/classpath/native/logging path, использованный engine, обязан входить в подписанный manifest. Локальная подмена `version.json`, Fabric/Quilt profile, JAR или logging config fail-closed блокирует запуск. В `0.10.3` production-материализаторы готовы для Vanilla, Fabric и Quilt; Forge/NeoForge installer adapters и настоящий графический Minecraft E2E пока не объявляются готовыми.

Прямое разрешение установленного client tree:

```bash
neverruntime compatibility \
  --root .neverlauncher/client \
  --version 1.21.1
```

## Компоненты

- **Backend API** — единый `/api/v1`, миграции PostgreSQL, подписанные манифесты, авторизация и серверные сессии, Redis rate limiting, доверенные proxy, local/S3-хранилище, резервное копирование, диагностика и ServerBridge.
- **CLI `nl`** — рабочие сценарии установки, авторизации, администрирования, операций, пакетов, релизов и runtime через `/api/v1`; исторические status-only семейства команд удалены.
- **NeverRuntime** — Rust runtime/CLI для Ed25519-проверки, потоковой загрузки и SHA-256, восстановления клиента, определения Java, построения плана запуска и запуска процесса.
- **Desktop** — Tauri-адаптер поверх NeverRuntime с системным защищённым хранилищем учётных данных и контролируемыми JVM-процессами.
- **Admin** — Vite-приложение в неизменяемом production-образе Nginx с CSP.
- **ServerBridge** — реальные плагины Velocity/Paper/Purpur, собираемые против API соответствующих платформ.
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

## Production E2E

Блокирующий релизный сценарий:

```text
миграции PostgreSQL -> bootstrap -> Velocity/Paper/Purpur
-> публикация подписанного Java fixture -> NeverRuntime: pinned Ed25519-проверка
-> потоковая загрузка/SHA-256 -> запуск JVM
-> вход -> разрешение -> отзыв -> запрет
```

Запуск в окружении с Docker, Gradle, JDK 21, Rust/Cargo, Go, PostgreSQL client, `curl` и `jq`:

```bash
bash e2e/scripts/run-minecraft-e2e.sh
```

## Production-развёртывание

Основные файлы:

```text
deploy/production/docker-compose.yml
deploy/production/env.production.example
deploy/production/TLS.md
deploy/production/README.md
```

## CI

`.github/workflows/ci.yml` — обязательный production CI. Он блокирует релиз при ошибках policy/preflight, Go/contracts, Admin/Desktop, NeverRuntime/Tauri, ServerBridge, production-контейнеров или полного PostgreSQL + Redis + Minecraft E2E.

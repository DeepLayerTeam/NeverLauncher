# NeverLauncher 0.10.2

NeverLauncher — self-hosted LauncherOps-платформа для Minecraft-проектов. Версия `0.10.2` переводит **Vanilla + Java runtime** в рабочий production-контур: CLI материализует официальный Vanilla-клиент из Mojang metadata с проверкой upstream-хешей, а NeverRuntime автоматически выбирает либо устанавливает проверенный Temurin JRE нужной major-версии перед запуском.

## Рабочий контур

```text
Mojang metadata -> Vanilla materializer -> проверенное client tree -> SHA-256 package/release
                -> подписанный immutable manifest -> NeverRuntime -> Managed Java -> JVM
```

Сохраняется весь контур `0.10.1`: Compatibility Engine, signed metadata trust boundary, immutable published releases, verify/repair/rollback, Ed25519 key lifecycle, SBOM/provenance, Backend API, Desktop и ServerBridge.

## Managed Java 0.10.2

NeverRuntime больше не требует заранее установленную подходящую Java. Перед построением/выполнением launch plan он:

1. получает требуемую major-версию из signed manifest и Mojang `javaVersion.majorVersion`;
2. отклоняет конфликт между manifest и Mojang metadata;
3. принимает custom Java только если профиль разрешает `allowCustomPath` и версия совпадает;
4. для `distribution=system` требует подходящую системную Java;
5. для `temurin`/`any` использует подходящую системную JVM либо устанавливает Temurin JRE через Adoptium API;
6. проверяет platform, размер и SHA-256 архива, скачивает через HTTPS во временный файл, безопасно распаковывает в staging и атомарно публикует runtime;
7. после установки повторно выполняет `java -version` и принимает только требуемую major-версию;
8. повторные запуски используют проверенный локальный runtime cache.

Поддерживаемые managed major-версии в `0.10.2`: Java 8, 17, 21 и 25.

Ручная установка/проверка Managed Java:

```bash
neverruntime java ensure --major 21 --distribution temurin
```

Desktop использует тот же NeverRuntime installer; установка Java не дублируется в JavaScript/Tauri UI.

## Vanilla materializer 0.10.2

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

## Compatibility Engine

При `runtime.launch.classpathStrategy = "compatibility"` NeverRuntime читает подписанный `version.json`, разрешает `inheritsFrom`, Mojang rules, ordered classpath, native classifiers, JVM/game arguments и logging config. Для materialized Vanilla natives автоматически выбирается текущий каталог `natives/windows`, `natives/linux` или `natives/osx`.

Каждый metadata/classpath/native/logging path, использованный engine, обязан входить в подписанный manifest. Локальная подмена `version.json`, JAR или logging config fail-closed блокирует запуск. Fabric/Quilt/Forge/NeoForge installer adapters и настоящий графический Minecraft E2E не объявляются готовыми в `0.10.2`.

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

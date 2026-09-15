# NeverLauncher 0.10.1

NeverLauncher — self-hosted LauncherOps-платформа для Minecraft-проектов. Версия `0.10.1` добавляет рабочий **Compatibility Engine** в исполняемый NeverRuntime: Minecraft launch plan теперь может строиться из подписанного Mojang-compatible `version.json` с наследованием, rules, ordered classpath, natives и JVM/game arguments вместо перебора всех JAR-файлов.

## Рабочий контур

```text
Администратор -> пакет/релиз -> подписанный манифест -> NeverRuntime: загрузка/проверка/восстановление
              -> контролируемый запуск JVM -> ServerBridge: проверка входа -> отзыв -> запрет
```


## Сохранённый production-контур 0.10.0-P3.2v4

- опубликованный release нельзя изменить: upload/manifest/status mutation после `published` блокируются и на HTTP, и на repository слое;
- client lifecycle реально устанавливает, проверяет, ремонтирует, помещает orphan-файлы в quarantine и откатывает snapshot;
- `install first-run` создаёт автономный Compose из canonical embedded templates и принимает только pinned API/Admin image refs;
- Desktop package содержит фактические native artifacts и SHA-256, а verify перечитывает каждый файл;
- Ed25519 ключи ротируются через persistent registry, могут быть отозваны, attestation подписывается detached signature;
- SPDX SBOM строится из dependency manifests/lock-файлов, provenance — in-toto/SLSA v1 и входит в release bundle с отдельной Ed25519-подписью.

## Compatibility Engine 0.10.1

При `runtime.launch.classpathStrategy = "compatibility"` NeverRuntime:

1. читает `versionMetadataPath` или `versions/<minecraftVersion>/<minecraftVersion>.json` из уже проверенного release;
2. разрешает цепочку `inheritsFrom` с защитой от циклов и traversal;
3. применяет Mojang OS/architecture/feature rules;
4. строит детерминированный ordered classpath и native classifier plan;
5. разрешает `arguments.jvm`, `arguments.game` и legacy `minecraftArguments` с Mojang placeholders;
6. учитывает `javaVersion.majorVersion` перед запуском;
7. проверяет, что каждый использованный metadata/classpath path входит в подписанный manifest, иначе launch fail-closed блокируется.

`targetOs` и `executable` сохраняются в Backend repository и signed manifest; verify/sync не требуют артефакты другой ОС. В `0.10.1` это именно production compatibility core. Автоматические installer/resolver adapters Fabric/Quilt/Forge/NeoForge и managed Java относятся к следующим compatibility-релизам и здесь не объявляются готовыми.

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

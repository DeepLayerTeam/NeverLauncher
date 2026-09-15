# Политика безопасности NeverLauncher 0.10.2

NeverLauncher 0.10.2 использует модель безопасности, в которой критичные решения принимаются на стороне Backend API и ServerBridge, а Desktop Launcher не считается доверенной границей.

## Обязательные production-настройки

Для production-окружения используйте persistent backend и сильные секреты:

```env
NEVERLAUNCHER_ENV=production
NEVERLAUNCHER_REPOSITORY_DRIVER=postgres
NEVERLAUNCHER_SQL_DRIVER=pgx
NEVERLAUNCHER_DATABASE_DSN=postgres://neverlauncher:password@postgres:5432/neverlauncher?sslmode=disable
NEVERLAUNCHER_AUTH_TOKEN_SECRET=replace-with-at-least-32-random-bytes
NEVERLAUNCHER_PERSISTENT_SESSIONS=true
NEVERLAUNCHER_REQUIRE_PERSISTENT_STORE_IN_PRODUCTION=true
NEVERLAUNCHER_BACKUP_ROOT=/var/lib/neverlauncher/backups
NEVERLAUNCHER_CORS_ALLOWED_ORIGINS=https://admin.example.com
```

В production Backend API fail-closed отклоняет memory repository, слабый token secret, HTTP public URL, wildcard/пустой CORS allowlist, пересечение backup/storage каталогов и неполную S3-конфигурацию. Runtime-переменной с резервным паролем администратора нет: вход проверяет только сохранённый password hash. Первый администратор создаётся отдельным bootstrap-flow с одноразовым `NEVERLAUNCHER_BOOTSTRAP_TOKEN`.

## Backup и восстановление

Production backup хранится отдельно от рабочего storage в `NEVERLAUNCHER_BACKUP_ROOT`. Архив содержит PostgreSQL custom dump, реальные storage-объекты и manifest с SHA-256. Перед восстановлением используйте `nl backup restore-dry-run`; реальный `nl backup restore` требует точного `--confirm <backupId>` и явного выбора `--database true` и/или `--storage true`.

S3 работает fail-closed: Backend не имеет автоматического fallback на local storage при ошибке подключения или health-check.

Backup/restore выполняются внутри maintenance-lock: mutating API-запросы блокируются на время согласованного снимка или восстановления. Перед destructive restore автоматически создаётся safety backup. Для local storage восстановление подготавливается в соседнем каталоге и переключается атомарным `rename`; PostgreSQL `pg_restore` выполняется с `--single-transaction`.

## Подпись production-релиза

`SHA256SUMS.sig` — реальная Ed25519-подпись байтов `SHA256SUMS`, а не повторный checksum. Private key передаётся только через `--private-key` или `NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE`; он не включается в release bundle. Проверка требует отдельный доверенный public key через `--public-key` или `NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE`. Public key из самого bundle не принимается как trust anchor.

Source archive формируется из git-tracked файлов либо строгого allowlist при отсутствии `.git`, исключает symlink/secret paths и до формирования release manifest проходит secret scan. `release verify` fail-closed проверяет наличие, размер и SHA-256 каждого `required=true` artifact, затем SHA256SUMS, Ed25519 signature и detached подпись `PROVENANCE.json.sig`. Provenance имеет формат in-toto Statement / SLSA v1, а SBOM — SPDX 2.3 и строится из dependency manifests/locks.


## Жизненный цикл signing-ключей

`nl security rotate-key` создаёт новую Ed25519 пару через CSPRNG и сохраняет metadata в persistent `trusted-keys.json`; private key записывается с правами `0600`. Предыдущий активный ключ переводится в verify-only либо сразу отзывается по явному флагу. `nl security revocation-list --revoke <keyId>` фиксирует отзыв в registry, а verify-flow с `--registry-dir` отклоняет подпись от отозванного public key. `nl security attest` создаёт detached Ed25519 signature для указанного artifact.

Published package после перехода в `published` считается неизменяемым: загрузка файлов, изменение manifest/status и повторная публикация запрещены на HTTP и repository уровнях. Любое изменение содержимого выпускается новой версией.


## Managed Java и Vanilla supply chain

NeverRuntime `0.10.2` устанавливает Managed Java только из HTTPS metadata Adoptium/Temurin. Перед публикацией runtime в локальный cache проверяются ожидаемый размер и SHA-256 архива, platform metadata и фактическая major-версия через `java -version`. Загрузка выполняется во временный файл, распаковка — в staging; path traversal и внешние symlink после извлечения отклоняются, а рабочий каталог появляется только после атомарного rename. Повреждённый ранее установленный runtime помещается в quarantine и не используется для запуска.

Vanilla materializer получает Mojang `version_manifest_v2.json`, затем проверяет опубликованный Mojang SHA-1 для `version.json`, client/libraries/assets/native/logging artifacts и ожидаемый размер. SHA-1 здесь является upstream-идентификатором Mojang, а не внутренним trust primitive NeverLauncher: после материализации каждый файл получает SHA-256 и далее проходит стандартный signed immutable release lifecycle NeverLauncher. HTTP разрешён только для loopback fixture-тестов; внешние источники должны использовать HTTPS. Native ZIP распаковываются с проверкой traversal, symlink и escape за пределы целевого каталога.

## CORS

`NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` содержит явный список HTTPS origin через запятую. `*` в production запрещён. Специальный `e2e-production` разрешает HTTP только для loopback `localhost/127.0.0.1/::1` и предназначен исключительно для автоматизированного production E2E.

## Сообщение об уязвимостях

Если вы нашли уязвимость, не публикуйте её в открытых задачах до первичного разбора.

Рекомендуемый порядок:

1. Подготовьте описание проблемы.
2. Укажите затронутые компоненты: Backend API, CLI, Desktop Launcher, Admin Panel, ServerBridge, манифесты, storage или deployment.
3. Приложите минимальные шаги воспроизведения.
4. Укажите возможное влияние на пользователей или серверные проекты.
5. Передайте отчёт владельцу проекта через приватный security-канал, указанный в репозитории проекта.

## Критичная область безопасности

Критичными считаются проблемы, затрагивающие:

- обход авторизации или RBAC;
- подмену package/runtime/project manifests;
- подмену файлов клиента;
- обход SHA-256/integrity verification;
- небезопасный запуск Java/Minecraft;
- утечку refresh/session/server tokens;
- обход ServerBridge validate-join;
- выполнение произвольного кода;
- path traversal при работе с архивами и storage;
- доступ к чужим проектам, пакетам, audit events или backup artifacts.

## ServerBridge security

ServerBridge должен работать в deny-by-default режиме:

- сервер регистрируется через отдельный bridge token;
- validate-join вызывается на Backend API;
- heartbeat/audit-event пишутся на backend;
- недоступность backend трактуется как deny или degraded mode только при явном разрешении оператора;
- ротация server token должна быть штатной операцией.

## Compatibility Engine trust boundary

При `classpathStrategy=compatibility` `version.json`, родительские metadata из `inheritsFrom` и каждый JAR, попавший в resolved classpath, должны присутствовать в подписанном release manifest. NeverRuntime не доверяет локальному metadata-файлу только потому, что он находится в каталоге клиента. Backend также запрещает публикацию compatibility release без обязательного `versionMetadataPath` (по умолчанию `versions/<version>/<version>.json`) и отклоняет traversal/небезопасные пути.

Mojang rules обрабатываются до выбора library/native artifacts. Файлы с `targetOs` другой платформы не участвуют в verify/sync текущей ОС; `targetOs` и `executable` являются частью подписанного manifest metadata.

## Целостность пакетов

Для клиентских пакетов обязательны:

- file-level SHA-256 manifest;
- проверка целостности перед запуском;
- repair mode вместо слепого перезаписывания;
- release artifact checksums;
- запрет доверять локальному состоянию Desktop Launcher без server-side session.

## Псевдонимы совместимости

Backend API может читать устаревшие compatibility aliases только для миграции, но документация и production-развёртывание 0.10.2 используют канонические переменные:

- `NEVERLAUNCHER_DATABASE_DSN` вместо `NEVERLAUNCHER_DATABASE_URL`;
- `NEVERLAUNCHER_AUTH_TOKEN_SECRET` вместо `NEVERLAUNCHER_TOKEN_SECRET` или `NEVERLAUNCHER_JWT_SECRET`;
- `NEVERLAUNCHER_STORAGE_LOCAL_PATH` вместо `NEVERLAUNCHER_STORAGE_LOCAL_ROOT`;
- `NEVERLAUNCHER_REDIS_ADDR` вместо `NEVERLAUNCHER_REDIS_URL`.

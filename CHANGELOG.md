# Changelog

## 0.11.3 — SQL Connector

`0.11.3` добавляет первый внешний production auth provider поверх Connector SDK/Federation Core: SQL Connector для PostgreSQL, MySQL и MariaDB. Это не отдельный endpoint/manifest слой — `/api/v1/auth/login` и `/api/v1/admin/login` реально маршрутизируют password authentication в зарегистрированный SQL provider по `providerId`, после чего Federation Core разрешает external subject в canonical Never user и выпускает обычную Never session.

### SQL authentication runtime

- Конфигурация нескольких SQL providers через `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE`; DSN может ссылаться на отдельную secret environment variable через `dsnEnv`.
- Только NeverLauncher-generated `SELECT`: table/column mapping проходит identifier validation, lookup statements подготавливаются при startup, login values передаются bind-параметрами, произвольный SQL из login request не выполняется.
- PostgreSQL, MySQL и MariaDB; connect/query timeout, bounded pool, connection lifetime, startup health check и fail-closed registration.
- TLS включён по умолчанию для внешнего SQL provider; режимы с plaintext fallback (`sslmode=prefer`, `tls=preferred`) запрещены при `requireTls=true`, insecure certificate verification и plaintext требуют разных явных opt-in.
- Каждый lookup выполняется в read-only transaction и возвращает не более одной identity; ambiguous username/email блокируется как conflict.
- Mapping: external id, username, email, display name, status, groups, roles и Minecraft UUID; groups/roles понимают JSON arrays, comma-separated values и PostgreSQL `text[]`.

### Password compatibility

- Argon2id PHC verification с bounds на memory/time/parallelism.
- bcrypt с ограничением допустимого work factor.
- PBKDF2-SHA256 (включая Django-style format) с минимальным iteration policy.
- Legacy SHA-256 выключен по умолчанию и требует `allowLegacySha256=true`.

### Federation / provisioning

- SQL provider может работать в `explicit-only` или `jit` provisioning mode.
- `jit` после успешной SQL password verification атомарно создаёт canonical Never user + external `auth_identity`; исходная пользовательская таблица остаётся read-only и не мигрируется в NeverLauncher.
- Canonical user ID стабильно выводится из `(provider, subject)`, а не из email.
- Совпадение внешнего email с уже существующим Never user не используется для auto-linking и завершается conflict, требуя явной связи identity.
- JIT federated user не получает фиктивный local-password identity.

### Production hardening

- Docker build теперь копирует `go.sum` и публичный `services/api/pkg`, поэтому production image действительно собирает Connector SDK/Federation Core.
- Добавлены executable tests на prepared/bound queries, read-only transaction, PostgreSQL arrays, TLS fallback policy, duplicate identity detection, Argon2id/bcrypt/PBKDF2/legacy password compatibility, JIT provisioning и запрет email auto-linking.
- Unknown identifier выполняет algorithm-equivalent dummy password work; identifier/password имеют верхние bounds, чтобы снизить timing enumeration и resource-abuse поверхность.
- PostgreSQL JIT provisioning сериализуется transaction-scoped advisory lock по normalized email, поэтому case-insensitive email conflict остаётся fail-closed и при конкурентных первых входах.

## 0.11.2 — Connector SDK + Federation Core

`0.11.2` переводит рабочий local password login на общий Federation Core. Встроенный `local` provider использует тот же публичный Connector SDK, который предназначен для SQL/HTTP/OIDC/Microsoft connectors следующих релизов; прямой password-check в `/auth/login` и `/admin/login` больше не является отдельным auth engine.

### Connector SDK

- Добавлен импортируемый Go SDK `services/api/pkg/authconnector` с typed metadata, capabilities, canonical provider identity, password/browser auth, refresh, profile resolution, identity linking и revoke interfaces.
- Capabilities являются исполняемым контрактом: registry и conformance suite отклоняют connector, который заявляет capability без соответствующего интерфейса.
- Добавлен reusable `authconnector/conformance` testkit; встроенный `local` connector проходит его в backend test suite.
- Connector errors имеют стабильные typed codes (`invalid_credentials`, `identity_disabled`, `unavailable`, `conflict`, `identity_not_found`) вместо сравнения строк ошибок.

### Federation Core

- Добавлен concurrent-safe provider registry и единый password-auth dispatch. `providerId` поддерживается в canonical `/api/v1/auth/login` и `/api/v1/admin/login`; отсутствие значения означает `local`.
- После успешной проверки credentials provider возвращает только authentication proof/identity. Federation Core обязательно разрешает `(provider, subject)` через `auth_identities` в canonical Never `User`; provider token не становится Never access token.
- Реализовано explicit-only identity linking с защитой от silent reassignment одного subject другому Never user.
- Локальный provider теперь реально зарегистрирован через SDK и обслуживает production login. MFA, RBAC, access/refresh sessions и audit выполняются после canonical identity resolution.
- Новые users при создании получают persistent `local` identity; successful federation login обновляет snapshot claims и `last_authenticated_at`.

### Persistence / API

- Migration `0005_federation_core_0112.sql` расширяет `auth_identities` provider metadata (`email`, `username`, `display_name`, `claims`, `last_authenticated_at`) и backfill-ит локальные identity.
- Repository получил рабочие get/list/save/touch операции для canonical identities в memory и PostgreSQL implementations.
- `GET /api/v1/auth/providers` показывает реально зарегистрированные providers/capabilities/health до login; `GET /api/v1/auth/identities` возвращает identity links текущего Never user без provider secrets/claims.
- OpenAPI login schema получил `providerId`; canonical auth capabilities теперь объявляют активный Federation Core и registry providers.

### Verification

- Backend integration test проверяет provider discovery, local login через Federation Core, canonical identity endpoint и дальнейший session refresh/revoke flow.
- Federation unit tests проверяют canonical resolution и fail-closed отказ для authenticated, но не связанной external identity.
- SDK conformance tests проверяют соответствие capability interfaces и health contract.

## 0.11.1 — Auth Core hardening + persistent sessions

`0.11.1` переводит authentication state с process-local registry/snapshot semantics на нормализованный PostgreSQL auth core и закрывает replay refresh token на уровне token family.

### Persistent session core

- Добавлена migration `0004_auth_core_0111.sql` с `auth_sessions`, `refresh_token_families`, `refresh_tokens`, `auth_identities`, `mfa_methods`, `recovery_codes` и `auth_events`.
- В PostgreSQL-режиме login/refresh/active/revoke/list используют общую БД как source of truth; memory backend остаётся только для dev/test.
- Refresh-token rotation сохраняет consumed-token history. Повторное использование старого token помечает family как compromised, отзывает текущий token и всю session.
- Ограничение числа сессий применяется транзакционно и отзывает соответствующие token families.
- Старые 0.10.x persistence snapshots мигрируются в нормализованные auth tables при первом запуске после обновления.

### MFA persistence

- TOTP state вынесен из общего runtime snapshot в `mfa_methods`; TOTP secrets хранятся encrypted at rest.
- Recovery codes хранятся отдельно в `recovery_codes` как hashes и потребляются атомарным `UPDATE ... WHERE status='active'`.
- Несколько Backend instances читают единое MFA/session state непосредственно из PostgreSQL.
- `currentCodeForSmoke` удалён из production enrollment response; тест получает enrollment secret и сам вычисляет код.

### Verification

- Добавлен regression test на refresh-token replay: replay старого token обязан отозвать session и отклонить ранее выданный current token.
- Offline backend test suite проходит с `neverlauncher_nopgx`; production pgx test в изолированном окружении требует заранее доступный module cache/registry.

## 0.11.0 — Minecraft Compatibility Release

`0.11.0` завершает compatibility-линию `0.10.1`–`0.10.7` и переводит её в release-grade состояние: Compatibility Engine, Managed Java, Vanilla/Fabric/Quilt/Forge/NeoForge materializers, actual Minecraft Client E2E и публичная CI-матрица теперь связаны с production release bundle machine-verifiable certification.

### Release-bound compatibility certification

- `nl release build` принимает `--compatibility-matrix`, `--compatibility-targets` и `--source-commit`; matrix повторно валидируется до формирования release checksums.
- В certified bundle добавляются `COMPATIBILITY_TARGETS.json`, `COMPATIBILITY_MATRIX.json` и `COMPATIBILITY_CERTIFICATION.json`.
- Certification требует совпадение product version/commit/run ID, exact target set, PASS всех required targets, `exitCode=0`, mandatory actual-client checks, immutable resolved loader versions и валидный `evidenceSha256`.
- Target definition и matrix хешируются SHA-256; certification фиксирует их digests, required/passed target sets и loader families.
- Все compatibility artifacts входят в `RELEASE_MANIFEST.json` как required, попадают в `SHA256SUMS` и защищаются общей Ed25519 release signature.
- `release verify` продолжает проверять cryptographic integrity candidate bundle; `release publish-check` для `0.11.0+` дополнительно fail-closed требует валидную compatibility certification.
- `scripts/release/build-release.sh` умеет собирать certified bundle через `NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE` + exact `NEVERLAUNCHER_SOURCE_COMMIT`; без matrix он явно создаёт только CI release candidate.

### Compatibility release hardening

- `release doctor` проверяет compatibility target definition и наличие public compatibility workflow/tooling.
- Runtime matrix сообщает release-bound certification как реализованную capability.
- Repository policy закрепляет обязательность certification primitives и предотвращает возврат к publish без фактического matrix evidence.
- Восстановлен отсутствовавший во входном `0.10.7` `runtime/neverruntime/src/bin/neverruntime.rs`; clean Cargo binary target снова имеет source file.
- Исторический hardening `0.10.7` сохранён: exclusive materialization lock, bounded retry, symlink-safe tree, deterministic generated state и строгий CI evidence.

## 0.10.7 — Compatibility stabilization

`0.10.7` стабилизирует весь Minecraft compatibility-контур `0.10.1`–`0.10.6` без добавления нового loader API: исправлены реальные гонки materialization, transient upstream failures, symlink/path escape, stale generated natives, portable atomic replacement и более строгая проверка CI evidence.

### Materialization lifecycle

- Vanilla/Fabric/Quilt/Forge/NeoForge CLI materializers теперь берут exclusive lock на конкретный `clientDir`; параллельная сборка одного дерева не может одновременно перезаписывать metadata/libraries/assets/processors.
- Stale lock старше двух часов безопасно вытесняется; обычное ожидание ограничено и завершается явной ошибкой вместо повреждения client tree.
- `clientDir` и существующие компоненты destination path проверяются через `Lstat`; symlink-компоненты отклоняются до записи.
- Asset logical paths валидируются до materialization virtual/resources tree.
- `buildClientPackage` теперь fail-closed отклоняет symlink artifacts, а не следует за ними при hashing.

### Download / filesystem hardening

- Все Minecraft/loader HTTP GET получили bounded retry для transient `408/425/429/500/502/503/504` и сетевых ошибок; `Retry-After` учитывается с верхним пределом.
- Client artifact ограничен 2 GiB и читается через `limit+1`, поэтому oversized response обнаруживается, а не молча обрезается.
- Повреждённый существующий artifact заменяется portable atomic sequence, работающей и там, где `rename` не заменяет destination напрямую.
- `natives/<os>` полностью пересобирается перед extraction, поэтому stale native libraries предыдущей materialization не попадают в новый signed package.
- Forge/NeoForge installer `data/` очищается и пересоздаётся перед processor execution.

### Runtime / CI evidence

- Compatibility Engine в NeverRuntime отклоняет symlink-компоненты при чтении metadata/classpath paths.
- Убран двойной `java -version` при проверке cached Managed Java.
- Восстановлен обязательный `runtime/neverruntime/src/bin/neverruntime.rs`; repository policy теперь блокирует Cargo `[[bin]]` без source-файла.
- Compatibility matrix aggregator теперь дополнительно требует `exitCode == 0`, healthy Paper evidence, совпадающий `manifestLoader` и полный набор обязательных evidence files.
- Добавлены regression tests для retry, materialization lock, symlink escape, unsafe asset paths, portable replace и symlink package artifacts.

## 0.10.6 — Public CI Compatibility Matrix + hardening

`0.10.6` расширяет actual Minecraft Client E2E до публичной CI-матрицы Vanilla/Fabric/Quilt/Forge/NeoForge и делает результаты machine-verifiable вместо ручной таблицы.

### Public compatibility matrix

- Добавлен canonical `compatibility/targets.json` без PASS/FAIL state; цели валидируются до построения dynamic GitHub Actions matrix.
- Новый `.github/workflows/compatibility.yml` запускает actual-client E2E на `main`, nightly и вручную, публикует per-target evidence и агрегированный `matrix.json`/`matrix.md` в Actions Summary/artifact.
- `scripts/compatibility/matrix.py` fail-closed проверяет completeness, duplicate/missing targets, exact commit/run ID, Minecraft/loader/OS/arch и concrete loader version; mutable `latest-stable` не принимается как resolved result.
- Добавлены regression tests агрегатора для валидного evidence, mutable resolved loader и commit mismatch.

### Generic actual-client E2E

- `run-minecraft-e2e.sh` теперь выполняет тот же production path для Vanilla, Fabric, Quilt, Forge и NeoForge; loader/profile больше не hard-coded как Vanilla.
- Compatibility mode поднимает обязательный Paper node и выполняет materialize → package verify → canonical API upload → signed immutable publish → clean sync → actual Minecraft → world join → revoke/deny.
- Concrete loader version извлекается из materialized package и повторно сверяется с опубликованным signed manifest.
- Исправлена 0.10.5 проверка manifest, где `jq` использовал не переданный `$mc`; в 0.10.6 Minecraft/loader/version передаются явно и проверяются fail-closed.

### Hardening

- `publish-client-package.py` запрещает symlink-компоненты package path и использует strict root containment перед чтением artifact.
- Compatibility result формируется wrapper-ом даже для failed E2E и содержит обязательные evidence checks; агрегатор не доверяет job name или ручному status.
- Repository policy запрещает manual PASS в target definition, требует public workflow/aggregator и generic actual-client primitives.
- Восстановлен `runtime/neverruntime/src/bin/neverruntime.rs`, отсутствовавший во входном архиве 0.10.5 при объявленном Cargo binary target.

## 0.10.5 — настоящий Minecraft Client E2E

`0.10.5` заменяет Java fixture в главном production E2E на реальный Minecraft Java Client и делает фактический вход клиента на сервер блокирующим release gate.

### Real client pipeline

- E2E материализует Minecraft 1.21.1 из официального Mojang `version_manifest_v2`, включая client JAR, libraries, assets, natives и logging config.
- Полученное дерево проходит полный локальный `nl client verify` до публикации.
- Новый `e2e/scripts/publish-client-package.py` повторно SHA-256-хеширует каждый artifact, загружает полный package через канонический `/api/v1`, сверяет backend checksum/size и публикует Ed25519-signed immutable release.
- NeverRuntime скачивает опубликованный release в чистый client root и повторно проверяет pinned Ed25519 signature и SHA-256 всех файлов.
- Настоящий Mojang client запускается под Xvfb/software OpenGL с `--quickPlayMultiplayer` и подключается к настоящему Paper 1.21.1.
- Release gate требует одновременно `neverlauncher.join.allowed username=E2EPlayer` и серверную строку `E2EPlayer joined the game`; простого protocol handshake недостаточно.
- После отзыва launcher session повторная попытка входа проверяет fail-closed deny; Velocity/Purpur сохраняют дополнительное protocol-level bridge покрытие.

### NeverRuntime

- Восстановлен фактический binary source `runtime/neverruntime/src/bin/neverruntime.rs`, который отсутствовал в переданном `0.10.4`, несмотря на объявленный Cargo `[[bin]]`.
- Добавлен `launch_with_timeout` и CLI-флаг `--max-runtime-seconds`: runtime корректно завершает дочерний game process после ограниченного CI-интервала и возвращает `timedOut` в JSON result. Обычный production `launch()` сохраняет прежнее поведение без timeout.
- Размер tail runtime log для launch evidence увеличен до 512 KiB.

### CI

- Production E2E job переведён на 90 минут и устанавливает Xvfb/OpenGL/X11/audio runtime, необходимый настоящему клиенту Minecraft на Ubuntu runner.
- CI artifact теперь содержит materialization verify, опубликованный package, signed manifest, clean sync result, actual Minecraft launch result и health/bridge diagnostics.

## 0.10.4 — Forge + NeoForge

`0.10.4` добавляет рабочую materialization-цепочку Forge и NeoForge поверх `0.10.3` Fabric + Quilt. Реализация использует настоящий processor-based installer format, а не декларативный install-plan.

### Forge / NeoForge installer pipeline

- Добавлены `nl runtime forge-install`, `forge-package`, `neoforge-install`, `neoforge-package`.
- Версия Forge выбирается по official Maven metadata для конкретной Minecraft-версии; NeoForge фильтруется по соответствующей ветке `major.patch`.
- `latest-stable` разрешается в concrete loader version до формирования release.
- Official `installer.jar` скачивается по HTTPS и проверяется по Maven `.sha1`; custom mirror требует явный URL/checksum.
- Installer JAR реально разбирается: читаются `install_profile.json` и встроенный `version.json`.
- Встроенный `maven/` извлекается безопасно в `libraries/`; traversal и symlink отклоняются.
- Installer `data/` извлекается во внутреннее `.neverlauncher` состояние и не попадает в итоговый client package.
- Installer/runtime libraries материализуются с SHA-1/size verification; локально созданные processor outputs нормализуются фактическими digest/size.

### Processor Engine

- Выполняются client processors из `install_profile.json` через реальную Java JVM.
- Processor `Main-Class` читается из `META-INF/MANIFEST.MF`; classpath строится из pinned Maven coordinates.
- Реализованы installer variables `{ROOT}`, `{MINECRAFT_JAR}`, `{INSTALLER}`, `{LIBRARY_DIR}`, `{SIDE}` и `data` variables.
- Maven references `[group:artifact:version[:classifier][@ext]]` разрешаются в локальный `libraries/` path.
- `outputs` проверяются по SHA-1/SHA-256; tokenized hash values вида `{PATCHED_SHA}` и quoted digests поддерживаются.
- Уже корректный output позволяет безопасно пропустить processor при повторной материализации.
- Каждый processor имеет timeout; запуск идёт без shell interpolation.

### Runtime integration

- Child Forge/NeoForge `version.json` нормализуется и сохраняется в `versions/<id>/<id>.json`.
- Итоговый profile использует существующий `inheritsFrom` Compatibility Engine без отдельного launch fallback.
- `runtime matrix` теперь объявляет processor-based Forge и NeoForge materializers готовыми.
- Legacy Forge pre-1.13 остаётся явно вне scope `0.10.4`, вместо ложного статуса поддержки.

### Проверки

- Добавлен полный локальный fixture: Vanilla base -> verified installer -> embedded Maven -> processor execution -> output digest -> child profile -> Never client package.
- Отдельно проверяются Forge/NeoForge Maven version selection, несовместимая Minecraft/NeoForge ветка, Maven classifier/extension paths и archive traversal.
- Восстановлен отсутствовавший в входном `0.10.3` binary source `runtime/neverruntime/src/bin/neverruntime.rs`, на который уже ссылался `Cargo.toml`.

## 0.10.1 — Compatibility Engine

0.10.1 переносит разрешение Minecraft launch metadata в исполняемый NeverRuntime и убирает fallback-планы из production runtime path. Compatibility Engine работает по подписанному содержимому immutable release и строит детерминированный план запуска из реального Mojang-compatible `version.json`.

### Исполняемый Compatibility Engine

- NeverRuntime получил отдельный `compatibility` engine: разрешение цепочки `inheritsFrom`, объединение version metadata, Mojang library/rule evaluation, OS/architecture/features rules, ordered classpath, native classifiers, `arguments.jvm`/`arguments.game`, legacy `minecraftArguments`, Java major version и стандартные Mojang placeholders.
- `classpathStrategy=compatibility`/`mojang` теперь используется непосредственно `Desktop -> NeverRuntime -> JVM`: main class, classpath и аргументы берутся из проверенного metadata, а не из перебора всех JAR-файлов.
- Все metadata и classpath paths, которые использует Compatibility Engine, обязаны входить в подписанный release manifest; локальный неподписанный `version.json` или JAR fail-closed блокирует запуск.
- Для multi-platform release NeverRuntime учитывает `targetOs`: чужие OS artifacts не блокируют verify/sync и не попадают в manifest classpath.
- Java constraint из version metadata участвует в pre-launch проверке совместимости JVM вместе с policy manifest.

### Backend / release integration

- `RuntimeLaunch` поддерживает `versionMetadataPath` и feature flags для Mojang rules; при отсутствии явного пути применяется `versions/<minecraftVersion>/<minecraftVersion>.json`.
- Backend проверяет compatibility metadata path на traversal и не публикует compatibility release без обязательного подписанного `version.json`.
- Рекомендуемый launch template и runtime requirements переведены на `classpathStrategy=compatibility` без статического Fabric/mainClass placeholder.

### CLI и runtime binary

- Product runtime commands больше не создают fallback launch plan при отсутствии `version.json`, а loader metadata без `--metadata`/`--installer-profile` отклоняется.
- Восстановлен фактический `neverruntime` binary, требуемый release pipeline и production E2E: `verify`, `sync`, `launch`; добавлена команда `compatibility` для прямого разрешения локального signed client tree.
- Добавлены unit/regression tests для inheritance, Mojang rules/features, Maven paths, placeholders, path traversal и backend publish validation.

## 0.10.0-P3.2v4 — Production hardening

P3.2v4 завершает следующий production-контур рабочим кодом: опубликованные релизы становятся неизменяемыми, client/desktop lifecycle выполняет реальные файловые операции, first-run становится автономным, а key lifecycle и supply-chain metadata получают фактическую криптографическую и dependency-backed реализацию.

### P3.2v4 — immutable/client/desktop/supply-chain

- Published release стал immutable на HTTP и repository слоях: после `published` запрещены upload, manifest/status mutation и повторная публикация; изменение требует новой версии.
- `nl client install/update/verify/repair/cleanup/rollback` выполняют реальный локальный lifecycle: SHA-256/size verification, snapshots, quarantine orphan-файлов, selective repair и rollback предыдущего состояния.
- `nl install first-run` использует встроенную копию canonical `deploy/production`, не зависит от checkout и требует pinned API/Admin image refs (`@sha256:`); CI-policy проверяет синхронность embedded templates.
- `nl desktop package/verify` принимает только существующие native artifacts, фиксирует size/SHA-256 и отклоняет отсутствующие или изменённые файлы.
- `nl security rotate-key/revocation-list/attest` используют persistent Ed25519 key registry, реальные key pairs, отзыв ключей и detached signatures; release verification может учитывать revocation registry.
- SBOM формируется из реальных Go/npm/Cargo/Gradle dependency manifests/locks в SPDX 2.3; provenance формируется как in-toto Statement с SLSA v1 predicate, hashes artifacts/materials и подписывается Ed25519 (`PROVENANCE.json.sig`).
- Production release bundle включает отдельный проверяемый Desktop package и требует signed provenance attestation.

### Безопасность и конфигурация

- Удалён fallback входа администратора через конфигурационный пароль: login принимает только пароль, хеш которого хранится у пользователя. Добавлен regression-test против повторного появления обхода.
- Production-конфигурация валидируется fail-closed до запуска API: PostgreSQL/pgx, сильный token secret, HTTPS public URL, отдельный backup root, storage и явный CORS allowlist обязательны.
- CORS wildcard удалён; preflight незнакомого origin блокируется, разрешённый origin отражается только из allowlist.
- S3 больше не переключается молча на local storage: ошибка инициализации или health-check останавливает Backend API.
- Admin UI больше не предзаполняет логин и пароль администратора.

### Backup и restore

- Backup создаёт реальный PostgreSQL custom dump через `pg_dump`, сохраняет фактические storage-объекты, JSON-снимки состояния и SHA-256 каждого файла в потоковый `tar.gz`.
- Backup хранится в отдельном `NEVERLAUNCHER_BACKUP_ROOT`; архив сначала пишется во временный файл, синхронизируется и атомарно переименовывается.
- `restore-dry-run` безопасно распаковывает архив во временный каталог, запрещает traversal/необычные tar entries, сверяет размеры/SHA-256 и проверяет PostgreSQL dump через `pg_restore --list`.
- Добавлен реальный `POST /api/v1/operations/backups/{backupId}/restore`: PostgreSQL восстанавливается через `pg_restore`, storage — через текущий storage driver. Разрушительная операция требует точного подтверждения `backupId` и явного выбора database/storage.
- CLI `nl backup restore` вызывает реальный restore и требует `--confirm <backupId>` плюс `--database true` и/или `--storage true`.

### Очистка и release gates

- Удалены пять неиспользуемых legacy handler-файлов поколений API 5.4–7.8; используемые общие helpers вынесены отдельно.
- `release doctor` запускает repository policy, version alignment и OpenAPI validation и больше не выдаёт ложный `production-ready`; полный production gate выполняется строгим preflight.
- `NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh` требует pgx, frontend, Tauri, ServerBridge и release bundle и fail-closed останавливается при недоступном обязательном контуре.
- Production E2E использует отдельный `e2e-production`: все production guards остаются включены, HTTP разрешён только для loopback тестового API.

### Production completion поверх hardening

- Docker API image и canonical Compose теперь детерминированно готовят writable storage/backup volumes для непривилегированного UID `10001`; отдельный init-service исправляет ownership существующих named volumes до старта API.
- `release sign/verify` используют настоящий Ed25519 с внешним private/trusted public key. `release verify` fail-closed валидирует каждый required artifact, SHA-256 и signature.
- Pipeline CLI выполняет настоящие Backend `validate → sign → stage → smoke-test → publish` операции; storage audit/consistency сканируют реальные объекты и SHA-256; migrate apply выполняет встроенный migrator, rollback идёт через подтверждённый backup restore; install verify/storage-check реально обращаются к Backend/storage.
- Старый first-run generator удалён: CLI копирует только canonical `deploy/production` template и не генерирует слабые `.env`/пароли.
- Backup/restore защищены maintenance-lock; перед restore создаётся safety backup, local storage переключается атомарным directory rename, PostgreSQL восстанавливается одной транзакцией.
- Source release package переведён на git-tracked/allowlist модель с запретом symlink/secret paths и обязательным secret scan.
- Production release bundle теперь требует реальные Admin Web, Desktop Web/native, NeverRuntime и Velocity/Paper/Purpur Bridge artifacts; CI полностью собирает и криптографически проверяет bundle.

## 0.10.0-P3.2v2 — Нормализация схем и усиление release-gates

P3.2v2 закрывает оставшиеся регрессии после P3.2 без добавления status-only слоёв или архитектурных заглушек.

### Документация и интерфейсы

- Актуальная документация, production checklist, TLS/E2E/smoke-гайды и README компонентов приведены к `0.10.0-P3.2v2` и переведены на русский язык.
- Admin UI и Desktop UI очищены от устаревших `0.10.0`-подписей и основных англоязычных операторских текстов.
- Версия синхронизирована в CLI, Backend, Admin, Desktop/Tauri, NeverRuntime, ServerBridge, deployment и E2E.

### CLI schemaVersion

- Исторические milestone-значения `schemaVersion` 4.x–8.x в CLI заменены на единую `cliSchemaVersion = "1.0"`.
- Специализированные форматы с собственными схемами, включая manifest/runtime, сохранены отдельно и не маскируются версией продукта.

### Preflight и CI

- Добавлен исполняемый `repository-policy.py`, который блокирует возврат CLI `schemaVersion` 4.x–8.x, рассинхронизацию версии, устаревшие docs/UI и известные англоязычные UI-регрессии.
- Policy-gate включён в `scripts/release/preflight.sh` и GitHub CI.
- `version-alignment.sh` расширен проверками NeverRuntime, Gradle ServerBridge, production image tag, E2E и актуальной документации.

## 0.10.0-P3.2 — Canonical API / CLI consistency

P3.1 completes the cleanup started in P3 without restoring compatibility shims or status-only product layers.

### API and implementation cleanup

- Fixed OpenAPI generation/validation after the P3 file renames; the checked-in `/api/v1` contract is generated from the real router and validated 1:1.
- Renamed the remaining `v5_*` implementation files and functions to product/domain names; no `/api/v5` router was reintroduced.
- Removed remaining P1/P2 implementation suffixes from manifest-signing, version-manifest and runtime wiring helpers.
- Canonical package/admin/security responses now point to `/api/v1` resources instead of historical endpoint hints.

### CLI

- Migrated all reachable Backend HTTP calls to `/api/v1`.
- Removed historical `platform`, `product`, `extension`, `public`, `beta`, `registry`, `lts` and standalone `deployment` command families that no longer have product functionality.
- Rewrote `nl --help` around the current install/auth/admin/operations/package/runtime/release surface without historical 4.x–8.x labels.
- First-run/install guidance now uses current installation verification instead of the removed beta-smoke command.

### Tests and documentation

- Converted canonical Backend HTTP checks that were incorrectly stored as production `.go` files into real `_test.go` integration tests.
- Restored active `/api/v1` regression coverage for CRUD, packages, signing, ServerBridge, backup, security and canonical-route enforcement.
- Updated the root README, CLI README, Backend API README and production deployment README for P3.1.
- Renamed release output from `dist/gitflic-release-*` to `dist/release-*` and `GITFLIC_RELEASE_DESCRIPTION.txt` to `RELEASE_NOTES.txt`; active release tooling is hosting-neutral.

## 0.10.0-P3 — Cleanup / Recovery

P3 restores a coherent production tree after repository cleanup without reintroducing historical compatibility/status layers.

### Recovery

- Physically completed the CLI split: the dispatcher `main.go` no longer duplicates domain command implementations.
- Physically completed the Backend split: `server.go` no longer duplicates canonical handlers, trusted-proxy or rate-limit code.
- Historical `/api/v2`–`/api/v5` routers remain removed; real product capabilities are registered under `/api/v1`.
- Restored the single canonical `schemas/openapi.yaml` and 1:1 router/OpenAPI validation.
- Removed preflight/release-script references to deleted fake/RC/stable/GitFlic smoke files.

### P2 production behavior restored

- Desktop uses NeverRuntime directly.
- Native OS credential storage is used for auth session secrets; there is no plaintext token fallback.
- JVM launch is supervised and logs stream to disk instead of buffering the whole process output.
- NeverRuntime downloads and SHA-256 verification are streaming.
- S3 upload uses disk spooling + incremental SHA-256 instead of buffering the object in memory.
- Redis-backed rate limiting, trusted proxies, production Admin image, CSP and production Compose are active again.
- Real Velocity/Paper/Purpur E2E is restored.

### Contracts / tests

- Canonical Backend tests now exercise `/api/v1` for CRUD, package publishing, security hardening, backup and ServerBridge.
- Historical API paths are tested as absent instead of being re-enabled for regression compatibility.

## 0.10.0-P0 — Production P0 Hardening

P0-патч закрывает критические security/database/release-integrity проблемы стабильной 0.10.0 без расширения продуктового API.

### Security

- Bootstrap owner защищён одноразовым `NEVERLAUNCHER_BOOTSTRAP_TOKEN`; plaintext токена не сохраняется в PostgreSQL.
- Состояние установки хранится в `neverlauncher_installation_state`; повторный bootstrap блокируется, после первого проекта фиксируется `installation_completed=true`.
- Mutating admin/release/extension endpoints предыдущих API-поколений требуют действительную session/permission.
- Desktop Launcher fail-closed проверяет Ed25519 manifest signature и точное совпадение pinned public key перед download/repair/build-launch-plan/launch.

### Database

- Добавлен исполняемый production migration runner с `schema_migrations`, SHA-256 checksum и PostgreSQL advisory lock.
- `nl db migrate apply` реально применяет embedded migration chain через `psql`.
- Backend автоматически применяет migrations или при отключённом auto-migrate отказывается стартовать при pending/checksum mismatch; `/ready` проверяет ту же цепочку.
- Baseline миграция нормализует исторические PostgreSQL layouts в текущую SQLRepository-схему и fail-closed останавливается на несопоставимых legacy file rows.

### Release integrity

- Production `build-release.sh` собирает Backend только с pgx и больше не имеет `neverlauncher_nopgx` fallback.
- Неизвестный repository driver больше не приводит к молчаливому переходу на in-memory repository.

### Проверено

- `go test ./...`, `go vet ./...` для CLI.
- `go test -tags neverlauncher_nopgx ./...`, `go vet -tags neverlauncher_nopgx ./...` для offline Backend контура.
- `scripts/release/preflight.sh` проходит для `0.10.0-P0` в offline-контуре.
- Full pgx/Cargo/live PostgreSQL проверки требуют среды с соответствующими зависимостями.

## 0.10.0 — Stable LauncherOps Platform

NeverLauncher 0.10.0 — первый стабильный product-релиз self-hosted LauncherOps Platform для Minecraft-проектов. Релиз фиксирует стабильный контур Backend API, CLI `nl`, Admin UI, Desktop Launcher, ServerBridge для Velocity/Paper/Purpur, production deployment, package delivery, runtime resolver, diagnostics, audit, backup/restore baseline и release gates.

### Добавлено

- Backend API слой Stable Release: `/api/v5/stable-release/status`, `/readiness`, `/components`, `/e2e`, `/artifacts`, `/final-report`.
- CLI-группа `nl stable`: `status`, `readiness`, `components`, `e2e`, `artifacts`, `final-report`, `smoke`.
- Миграция `0103_stable_release_0100.sql`.
- Stable smoke-gate `scripts/smoke/stable-required/stable-release-smoke.sh`.
- Минимальный комплект `schemas/` и `examples/` для GitFlic Release, OpenAPI, package/runtime/project/profile manifests, ServerBridge и extension runtime.

### Изменено

- Версия продукта синхронизирована как `0.10.0` во всех основных компонентах.
- `scripts/release/preflight.sh` включает AdminOps, Security Freeze, RC1, RC2 и Stable Release gates.
- Production deployment использует единые canonical env-переменные: `NEVERLAUNCHER_DATABASE_DSN`, `NEVERLAUNCHER_AUTH_TOKEN_SECRET`, `NEVERLAUNCHER_STORAGE_LOCAL_PATH`, `NEVERLAUNCHER_REDIS_ADDR`.
- Legacy smoke-скрипты приведены к текущей версии 0.10.0 и больше не ожидают 9.x artifacts.
- `SECURITY.md`, `.env.example`, E2E-документация и smoke-документация приведены к релизу 0.10.0.

### Проверено

- `scripts/release/preflight.sh` — обязательный offline release gate.
- `scripts/smoke/docker-required/production-compose-config.sh` — static production compose gate.
- `scripts/smoke/minecraft-required/minecraft-demo-kit-smoke.sh` — static Minecraft E2E demo-kit gate.
- `scripts/test/check-gitflic-publication.sh` — проверка GitFlic Wiki, release example и schema/example комплекта.

### Ограничения

- Native Tauri build требует локальной среды с Rust/Cargo.
- Full PostgreSQL/pgx режим проверяется отдельно через `NEVERLAUNCHER_PREFLIGHT_PGX=1` в среде с доступными Go-зависимостями и PostgreSQL.

## 0.9.13 — Release Candidate 2 / Compatibility Lock

RC2 зафиксировал compatibility policy для Backend API v5, CLI command surface, production config, ServerBridge contract, manifest schemas и SQL migration numbering.

## 0.9.12 — Release Candidate 1

RC1 зафиксировал feature freeze, release candidate gates, compatibility matrix, upgrade checks и release artifacts checklist.

## 0.9.11 — Security Freeze

Security Freeze зафиксировал auth hardening, ServerBridge security, package integrity и production guard.

## 0.9.10 — UX, AdminOps & Operator Experience

Релиз добавил AdminOps, operator flow, diagnostics, backup/restore UX и соответствующий smoke-gate.

## 0.9.9 — Production Deployment & Real E2E

Релиз добавил production compose, nginx contour, first-run bootstrap, Minecraft E2E demo-kit и production E2E endpoints.

## 0.9.8 — Build, Test & Release Gate

Релиз добавил единый `scripts/release/preflight.sh`, smoke-матрицу, GitFlic CI baseline и release-gate discipline.

## 0.9.7 — Release Cleanup & Version Alignment

Релиз синхронизировал версии, подчистил README/Wiki и подготовил ветку к стабильной 0.10.x-линейке.

# Changelog

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

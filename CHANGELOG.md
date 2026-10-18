## 0.21.10 — Everyday Lifecycle

## 0.22.2 — Schema Evolution Integrity

- Закреплён неизменяемый ProfileSnapshot на протяжении изменения и публикации релиза; отклоняются подмена snapshot, смена схемы и identity.
- Миграция 0057 с отложенным контролем исторических ревизий и DB-level защитой подписанных опубликованных манифестов.
- Безопасные копии данных в in-memory repository, точное чтение snapshot из PostgreSQL history, отказ от небезопасной перепубликации без подписи.
- Сохранена совместимость ранее подписанных v1 manifests без изменений или повторного подписания.


- Added project-authorized persisted-job listing with bounded pagination, status filtering, attempt history and audit deep links.
- Connected Admin backup/restore to real archive creation, inspection, verified dry-run and explicitly confirmed component restore with existing server step-up.
- Introduced dedicated self-service sessions/trusted devices workflow with revocation results and audit links.
- Added confirmation, error recovery and actual operation results for NeverExtensions registry, lifecycle and host management.
- Clarified synchronous restore vs durable jobs, including indeterminate HTTP disconnect handling.

# История изменений

Используется структура [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/). Источником текущей версии является `VERSION`; историю релизов следует сверять с Git-тегами и [GitHub Releases](https://github.com/DeepLayerTeam/NeverLauncher/releases), а не реконструировать задним числом.

## [Unreleased]

## [0.22.1] — Profile/Manifest Schema Evolution

- Added genuine Profile v2 persistence: SHA-256 digests, monotonic revisions, compare-and-swap updates and immutable PostgreSQL revision history with migration/backfill (`0056`).
- New release drafts freeze a Profile v2 snapshot in Manifest v2; backend and NeverRuntime sign, verify and validate the embedded snapshot.
- Preserved existing signed Manifest v1 payloads and signatures without any mass migration or re-sign.
- Prevented draft manifests being served as published and stopped duplicate release draft creation from replacing stored versions.
- Exposed actual profile revision history and optional optimistic update precondition; added regression tests and upgrade/rollback guidance.


## [0.22.0] — Admin General Availability candidate (certification required)

- Restored parity of Backend and CLI immutable PostgreSQL migration catalogs (0053–0055) and fixed current-schema regression tests.
- Updated repository policy for modular Admin UI and the durable rollback implementation without relaxing immutability, lock or signature checks.
- Added executable fail-closed production certification: version/OpenAPI/SDK reproducibility, Go race/vet/build, Admin production Vite build, live PostgreSQL/ServerBridge and browser E2E.
- Corrected live Playwright suite to use the canonical product version and check staging API readiness, version and build SHA; stale staging is rejected.
- Added real ServerBridge v3 GA operator probe: disposable Minecraft server save/drain/undrain, confirmed execution ACK and duplicate-request protection; failures block release.
- Embedded the build source commit in Backend status and Admin frontend metadata, and required the live staging E2E to match it. Production image and Linux build paths propagate the commit.
- Gated production release-candidate bundling on an Admin certificate from the same source SHA. The source version alone is **not** a GA approval.
- Documented actual deployment, SQL migration and safe rollback requirements in `docs/administration/ga-0220.md`.


### Документация

- Заполнены корневые руководства, каталог `docs/`, шаблоны GitHub, `.editorconfig` и `.gitattributes`.
- Добавлены указатели на актуальные исходники контрактов, проверки и production-конфигурации.

## [0.21.9] — ServerBridge Operations

- Проектно изолированный live-обзор ServerBridge: backend-фильтрация серверов, control history, topology и audit с проверкой `project:read` на проекте. Глобальный overview не изменён.
- Admin-карточки runtime, health, heartbeat/telemetry freshness, TPS/MSPT, игроков, heap, Java/Minecraft/loader, протокола и feature digest. Устаревшие показания явно показываются как неизвестные.
- Формы player.kick, message.broadcast, whitelist/ban, save, maintenance/drain, shutdown и server.console по отдельному праву, с подтверждением эффекта и повторной серверной проверкой RBAC/MFA.
- Контрольные команды посылаются в существующий долговечный ServerBridge v3 control API; браузер сохраняет idempotency key при потере HTTP-ответа и отслеживает настоящий ACK. Queued/dispatched/delivered/executed/failed/indeterminate не смешиваются.
- Оператор получил проектное `serverbridge:control` без `serverbridge:console` (миграция PostgreSQL, in-memory и fallback role). Добавлены тесты фронтенда и проектной изоляции Backend, документация. Замороженный протокол v3 не менялся.

## [0.21.8] — Release Workspace

- Полноценный пошаговый мастер релиза в Admin с созданием, редактированием, удалением и возобновлением серверных черновиков (PostgreSQL + CAS `revision`), с привязкой к владельцу/проекту.
- Выбор профиля/Minecraft/загрузчика, создание настоящего пакета, загрузка файлов и вызов реальных validate, Ed25519 sign, stage, integrity-check и signed runtime evidence API.
- Предпросмотр публикации и rollback через Unified Operations; постоянный Idempotency-Key и восстановление job по черновику после потери ответа. Отдельный job monitor с историей попыток.
- Добавлены миграция, OpenAPI маршруты, регрессионные тесты и руководство `docs/administration/release-workspace-0218.md`.
- Legacy `/smoke-test` остаётся проверкой integrity, а не запуском Minecraft: подтверждение реального smoke достигается только доверенным подписанным runtime evidence.

## [0.21.7] — Unified Operations

- Добавлен работающий единый lifecycle операций Admin/CLI/API `validate`, `execute`, `status`, `cancel`, `retry`, `attempts` для публикации пакетов и отката каналов.
- `channel-rollback` теперь исполняется в durable worker: хранение задачи и попыток, повторная авторизация перед побочными эффектами, scope leases и автоматическое восстановление после перезапуска.
- Имя rollback-релиза привязано к неизменяемому job ID, а не к текущему времени; одинаковый Idempotency-Key возвращает тот же job и релиз. Промежуточные файлы дописываются после сбоя, откат всегда повторно проверяет исходные digest, подпись и собственную целостность.
- Отмена разрешена только до начала работы; retry терминальной ошибки сохраняет тот же job/correlation ID, монотонные номера попыток и fencing; `succeeded` и `running` не перезапускаются.
- Добавлены экран Unified Operations в Admin и команды `nl adminops operation ...`; сохранена обязательная MFA/step-up и проектная изоляция.
- Добавлены регрессионные проверки идемпотентности rollback, жизненного цикла и ошибок доступа. Для успешного runtime-валидационного policy откат остаётся в `staged` до прохождения реальных проверок.

## [0.21.6] — Admin Foundation

- Переработан `apps/admin/src/main.tsx`: модульные Admin-экраны, браузерная маршрутизация, рабочий выбор доступного проекта, typed API-клиент, таблицы поиска/фильтрации/сортировки/пагинации и карточки записей.
- Доступность разделов и действий определяется ответом `/api/v1/admin/me`, включая полномочия выбранного проекта; проверки на Backend остаются обязательными.
- Подключены действующие CRUD-действия и загрузка/проверка/публикация пакетов; исправлена проверка пакета (теперь `POST /api/v1/packages/{packageId}/validate`).
- Серверные списки отображаются предметными таблицами и карточками вместо универсального JSON-вывода. Сложные подробности убраны в раскрываемые секции.
- Добавлены автономные Node-тесты авторизации, API-контрактов и трансформаций таблиц. Браузерная/серверная интеграционная сертификация на данном исходном архиве не проводилась.

## [0.21.5]

Исходный архив фиксирует версию `0.21.5`. Подробные исторические заметки об изменениях этого релиза в исходном файле CHANGELOG отсутствовали. Перечень фактически поставленных функций и список успешно сертифицированных платформ необходимо проверять по Git-тегу, исходникам и сертификатам CI.

[Unreleased]: https://github.com/DeepLayerTeam/NeverLauncher/commits/main
[0.21.9]: https://github.com/DeepLayerTeam/NeverLauncher/releases
[0.21.8]: https://github.com/DeepLayerTeam/NeverLauncher/releases
[0.21.7]: https://github.com/DeepLayerTeam/NeverLauncher/releases
[0.21.6]: https://github.com/DeepLayerTeam/NeverLauncher/releases
[0.21.5]: https://github.com/DeepLayerTeam/NeverLauncher/releases

## 0.25.8 — Desktop Textures UI

- Added the operational **Скины и плащи** Desktop workspace, with authenticated personal gallery, PNG upload, URL import, saved-asset selection, reset/delete, model/visibility controls and immutable revision history using existing production Backend texture routes.
- Implemented 2D/3D Minecraft model/cape previews with native skin atlas UVs, Classic/Slim geometry, draggable CSS 3D orbit and overlay layers; no third-party runtime dependency. Owner previews use bounded authenticated PNG fetch and revoke temporary object URLs on unmount.
- Added cancellable multipart progress for both local uploads and official Minecraft Services uploads; hardened official preview CDN allowlist and kept local Never/Yggdrasil credentials separate from official Minecraft profiles and capes.
- Added 10 TypeScript client regression tests (CAS, owner-only previews, progress, CDN restrictions, official session rotation), new `npm run test:textures` and the CI frontend test gate. Synced launcher versions, Tauri CSP and OpenAPI.
- See [Desktop textures workflow and release checks](docs/textures/desktop-textures-0258.md). **Certification:** pure TS tests and OpenAPI/version checks pass; full React/Vite/Tauri builds and real backend/official Minecraft E2E remain unverified in this offline environment.

## 0.25.7 — Official Minecraft Integration

- Implemented Microsoft OAuth2 device-code flow, Xbox Live + XSTS exchange, Minecraft Services bearer creation/refresh and live Java profile verification; the official identity remains separate from NeverLauncher local/Yggdrasil UUIDs and ServerBridge.
- Added authenticated official profile, owned cape selection/hide and PNG skin upload/reset against Minecraft Services; only the account's actual owned resources can be used. Official PNG uploads reuse the full PNG decoding and normalization pipeline.
- Added encrypted, Never-session-bound AES-GCM official tickets with 30-day ceiling and automatic Microsoft refresh rotation, strict upstream origin/response limits and bounded Microsoft polling.
- Connected a minimal functional Microsoft login, official skin/cape controls and explicit local/official launch selector in Desktop; official Minecraft uses `msa` and NeverRuntime refuses local authlib-injector/ServerBridge mixing.
- Added Go/TypeScript unit tests, config and deployment guide, CORS for the official ticket header and updated OpenAPI/version metadata. Live Microsoft/Xbox/Minecraft E2E and complete API/Desktop build remain release-blocking.
- See [Official Minecraft configuration and usage](docs/textures/official-minecraft-0257.md).

## 0.25.5 — Texture Service API & Ownership

- Finished the authenticated local-Minecraft texture selection lifecycle: list personal saved PNGs, preview private gallery assets, select by owned digest, reset to default, delete current selection and remove inactive library items.
- Added `0071_texture_service_0255.sql` with per-account saved texture items and inactive selection tombstones; upload/import now save reusable normalized assets transactionally, while CAS revisions and previous events remain immutable.
- Enforced PostgreSQL owner verification, skin/cape policy checks, cape grants, per-profile concurrency, denied foreign digests/UUIDs, and no reactivation of empty reset selections.
- Updated SHA-256 local/S3 GC to protect saved-but-inactive gallery objects; deletion releases per-user quota only after checking remaining assignment/library references, while physical content stays in the existing backup grace period.
- Added PostgreSQL integration scenarios for CAS, permissions, reset/delete, preview ownership and GC. Synced OpenAPI/SDKs and product version. See [Texture Service API and operations](docs/textures/texture-service-0255.md).
- **Certification:** full Backend compile, test PostgreSQL and real S3/local integration must pass on release infrastructure before a production rollout; later milestones provide official Minecraft/Yggdrasil signing and Desktop/Admin UX.

## 0.25.2 — Secure PNG Processing

- Implemented authenticated multipart skin/cape uploads with bounded complete PNG decoding, CRC and chunk integrity checks, Minecraft dimensions/model validation, resource ceilings and deterministic metadata-free NRGBA normalization.
- Added immutable SHA-256 local object writes and configured S3 storage integration, transactional verified-blob registration and CAS assignment replacement with owner/policy enforcement and persisted revision history.
- Added private owner preview, public-only digest image delivery with integrity verification, ETag, controlled cache duration and MIME hardening; local Yggdrasil profile URLs now reference verified managed blobs.
- Migration `0068` records upload events; schema/SDKs and product version updated. See [secure PNG processing and deployment](docs/textures/secure-png-processing-0252.md).
- **Certification:** processor/storage/model/migration unit tests can run offline. Full API build and PostgreSQL E2E must be performed with dependencies and a test database before production deployment. Signed Yggdrasil profiles, global quota/GC and Desktop UI remain separate roadmap milestones.

## 0.25.1 — Texture Identity & Data Model

- ServerBridge join tickets now use the immutable `minecraft_profiles.uuid` shared with local Yggdrasil; no new user-derived Minecraft UUIDs are issued.
- PostgreSQL migration `0067` introduces ownership-bound local/official texture identities, texture blob metadata, scoped skin/cape assignments, monotonic revisions, immutable revision snapshots, policy/cape grant records and proven legacy UUID aliases.
- Existing ServerBridge URL records are imported into canonical assignments without rewriting Minecraft UUIDs. Unmatched identities remain preserved in quarantine, not served as public textures; new profiles receive atomic lazy backfill.
- Added authenticated player read/selection/history operations with SQL transactions, revision conflict detection, strict model/visibility validation, ownership verification, limited bodies, fail-closed reads and audit events. API schema regenerated from the canonical route generator.
- **Scope:** this is the real data/identity layer, not full PNG upload, local/S3 delivery, Yggdrasil RSA signing or Desktop UI. Full Go/PostgreSQL integration certification remains required before a production rollout. See [deployment and migration guide](docs/textures/texture-identity-0251.md).

## 0.25.0 — Optional Components GA (certification-gated)

- Strengthened the real production release entrypoint: 0.25.0 requires an independently Ed25519-signed, exact-commit six-platform Optional Components GA evidence cohort **before** build output cleanup or product signing.
- Added signed-evidence checks for exact installer SHA-256, live Minecraft JVM launch, NeverGuard, ServerBridge anti-replay, owned component graph, signed actions, deterministic resolved plan, preset migration, adversarial and fault cases. Missing evidence is a hard failure.
- Replaced ephemeral release signing identities in the production workflow with an approved protected release key and trust policy; introduced a separate manually approved GA verifier workflow.
- Hardened the GA parser against duplicate JSON keys, symlinks, mismatched trust roots, oversized proofs and unbounded in-memory installer reads; added regression tests.
- Tightened portable component-ID validation in NeverRuntime to reject IDs containing consecutive dots, matching Backend rules.
- Synced product metadata to 0.25.0 and added [GA procedures and compatibility notes](docs/releases/0.25.0-optional-components-ga.md).
- **Status:** production release must remain blocked until real signed target attestations, successful Rust builds and real Minecraft/Guard/Bridge E2E are available. Test fixtures are not release certificates.

## 0.24.13 — Integration & Compatibility Certification

- Native CLI `verify`, `sync`, `sync-local` now accept an explicit signed component preset through the same v3 native resolver and transactional installer as Desktop, supporting exact selection verification without modifying signed manifests.
- Added an actual-binary Manifest v3/Catalog v5 E2E suite covering preset transitions, SHA-256/Ed25519, HTTP poison/503/truncation, safe file ownership, rollback/recovery, and fail-closed adversarial cases.
- Added six-target GitHub Actions matrix with Rust/Go execution, manual real Mojang Minecraft JVM launch, provenance-bound evidence collection and a strict incomplete/failed 0.24.13 gate.
- The signed clean-machine GA release gate remains independent. **No production certification is implied without runtime/Java, Guard/Bridge, and platform-specific evidence.**
- See [0.24.13 integration and certification guide](docs/releases/0.24.13-integration-compatibility-certification.md).

## 0.24.11 — Gravit OptionalFile / OptionalView Migration

- Added a real Go conversion path for recognized Gravit `updateOptional` declarations, exact-name dependency/conflict binding, supported required OS/arch/Java conditions, categories and safe File/ClassPath/JvmArgs/ClientArgs actions.
- Added a project-scoped Admin import panel and a read-only, CAS-guarded Backend migration preview bound to the draft package's real hashed optional file inventory. Standard signed Catalog v5 validation/save/sign remains authoritative.
- Unsupported move/rename, permissions, Gravit group/preset/trigger semantics, unsafe arguments and missing files produce per-field incompatibility reports and block automatic application.
- Added migration/model and HTTP lifecycle regression tests and [operator guide](docs/administration/gravit-optional-migration-02411.md). Full Backend and UI production builds require external dependencies not available in this environment.

## 0.24.9 — CLI Components Tooling

- Добавлены рабочие офлайн-команды `nl components validate|resolve|export|diff` с детерминированным JSON и структурированными ошибками.
- Проверка Manifest v3 / Catalog v1–v5, Ed25519 по независимому доверенному ключу, SHA-256 каталога и принадлежности optional-файлов.
- Расчёт выбранных компонентов, причин зависимостей, условий окружения, подписанных действий и сравнений между релизами без изменения манифеста.
- Тесты реальной Go/Ed25519 фикстуры, защиты от подмены, межмодульного совпадения resolver и воспроизводимости вывода.

## 0.24.8 — Admin Component Graph Editor

- Added a real Admin editor for signed-catalog topology, nested categories/groups, presets, component metadata, conditional rules and four signed optional actions.
- Release Workspace creates Manifest v3 packages and supports `optional` ownership for uploaded files, with server-side hashing.
- Added preview and CAS save of the complete catalog using the existing Backend validation and deterministic graph resolver; final digest and revision are recalculated server-side.
- Added repository-atomic draft catalog updates that can repair temporarily unassigned optional files without rewriting pinned identity or published snapshots.
- Added mandatory graph checks at Ed25519 signing, preventing bypass via legacy draft-manifest mutation.
- Added regression tests and [authoring guide](docs/admin-component-graph-editor-0248.md).

## 0.24.7 — Desktop Optional Components UI

- Подписанный пользовательский выбор компонентов поверх пресетов; native resolver проверяет зависимости, исключения и условия.
- Desktop preview: объяснения, SHA-256 diff, предварительный объём загрузки и явное подтверждение.
- Применение выбора к staging, восстановлению и запуску через один resolved plan.

## 0.24.6 — Resolved Download & Ownership

- Native release installer now uses a single deterministic, digest-bound resolved file plan for staging, download selection, verified live-file reuse, commit, launch identity and recovery. Durable download jobs pin this plan through pause/resume; old receipts remain readable.
- Byte-identical **previously owned** files are reused without redundant network/cache transfer or live replacement. Other selected artifacts continue through the real content-addressed SHA-256 cache and transactional staging. All selected outputs are reverified before switching.
- Retired files are restricted to the previous managed ownership record. Untracked player files cannot be claimed even when they match the published SHA-256. Locally modified managed files block destructive preset switches; repair of the same signed selection remains possible.
- Added Rust integration/regression tests for signed catalog v5, real install and preset transition, repair-safety conditions, plan identity corruption, rollback, and untracked file protection. See `docs/resolved-download-ownership-0246.md`.
- Go model and migration tests passed in the authoring environment. **Rust compilation/tests, complete Backend build and OS/Minecraft E2E are not certified** (Rust toolchain and several external Go dependencies unavailable). O04 permission entitlement limitation remains.

## 0.24.5 — Signed Optional Actions

- Catalog schema 5.0 signs and validates `File`, `ClassPath`, `JvmArgs` and `ClientArgs` actions; file targets must belong to their signed component. Go and Rust use a matching domain-separated v5 catalog digest.
- The native transactional installer stages only selected `File`/`ClassPath` paths; real Java launch plans append verified selected classpath JARs and restricted signed JVM/client arguments. Active signed release identity and installed preset are required, and optional executable inputs receive SHA-256 checks before launching.
- Optional arguments are constrained to explicit namespaces and safe single tokens: no JVM agents, classpath/entrypoint overrides, Java heap bypass or Minecraft authentication/session overrides.
- Desktop supports v5 native preview, file counts and display of signed actions; backend draft mutations, memory snapshot cloning, schema, PostgreSQL migration 0065 and version metadata are updated.
- Go model/migration tests and `go vet` pass. Rust fixture, positive launch-plan and rejection tests are added, but **Rust build/tests, full Backend/Desktop build and Minecraft E2E were not run** here and require CI certification before deployment.
- Entitlement issuer/verification for `permissions` remains the known 0.24.4 limitation.

## 0.24.4 — Conditional Component Resolution

- Catalog schema 4.0 with signed, versioned `conditions` schema 1.0 and Go/Rust matching domain-separated SHA-256 digest. The existing catalog 1.0/2.0/3.0 snapshots and manifest signatures remain compatible.
- Conditional evaluation is integrated with NeverRuntime's authoritative preset resolver, transactional staging, downloads, repairs, integrity checks and launch gate. Required/selected/dependency violations fail before IO; unavailable implicit defaults are excluded.
- OS, CPU architecture, signed Java target, Minecraft exact/SemVer versions, loader and loader SemVer conditions; explicit errors for unsupported combinations, version bounds and unsigned/unknown conditions.
- The Desktop uses native, pinned-key-verified conditional preview (not an unauthenticated client-side permission list); Go model exposes an explicit server-trusted environment for authorization decisions.
- Permissions default to deny on native runtime without a separately verified entitlement. **Full authenticated permission issuance/use is not part of this patch**, so components that require permissions cannot be enabled yet; this is a known release blocker for the complete O04 goal.
- PostgreSQL migration 0064 (both API/CLI), immutable release protection, deep-copy safety for memory repository, published catalog validation, Go tests, Rust cross-language fixture test and documentation.
- Full Rust/Desktop build, real Minecraft launches and PostgreSQL integration certification have not been executed in this environment.

## 0.24.3 — Dependency & Conflict Resolver

- Signed component catalog schema 3.0: strict semantic versions, dependency references and version ranges, version-scoped conflicts and mutually exclusive groups. v1/v2 catalog digests remain backward compatible.
- Go publication validates all signed constraints and every named preset, including cycles, unreachable dependencies, contradictory required components and impossible preset combinations; errors identify the relevant IDs and constraint.
- NeverRuntime resolves transitive dependencies into effective signed file sets and fails before download, repair, release switch and launch on invalid configurations. No unverified files, JVM flags or downloaded actions are synthesized from component choices.
- Desktop previews dependency-driven selection and reasons, including conflict/exclusion explanations; native resolver remains the sole authority for installation and launch.
- PostgreSQL migration 0063, in-memory deep-copy of rule slices, cross-language Go-signed fixture, Go resolver/migration tests and Rust fixture/tests.
- Validation limitation: native Rust/Desktop binary builds and real Minecraft integration tests are not certified by the checks performed in this environment.

## 0.24.2 — Component Topology & Presets

- Signed catalog schema v2 with `required`, `default`, explicit `visible`, `limited`, descriptions and bounded metadata.
- Nested categories and groups, depth/cycle/unknown-reference checks; named owner-signed presets and defaultPreset.
- Canonical topology digest across Go and native Rust; legacy catalog schema v1 unchanged.
- Native preset resolution now restricts actual transactional file staging, download, integrity check, repair and managed removal; selection persists in a crash-recoverable job and installed-release record.
- Desktop signed preset picker, selected components display, native launch gate requiring selected installed preset.
- PostgreSQL migration 0062 supports catalogs v1/v2 without relaxing published release immutability.
- No dependency/conflict/version solver, conditional policies or arbitrary optional actions in this release (reserved for 0.24.3–0.24.5).

## 0.24.1 — Signed Component Catalog (Manifest v3)

- Added an actual v3 release creation path in PostgreSQL and memory storage, a separate component catalog with stable IDs, file ownership references, monotonic draft revision and deterministic content digest.
- The existing Ed25519 package sign/stage/integrity/publish pipeline now signs the catalog with the release, and rejects missing, duplicated, orphan or unsafe optional file ownership. Published snapshots remain immutable through API and database triggers.
- NeverRuntime verifies the same catalog digest, manifest signature and component file membership before download/repair/launch; transactional v3 installations cannot activate with missing optional-owned component artifacts.
- Added Go validation tests, matching Rust integrity/signature tests and a fixture signed using the real Go Ed25519 serializer for cross-language verification. Legacy CLI updater refuses v3 rather than dropping its signed catalog.
- Deployment instructions and unverified platform/integration gates: `docs/optional-components-0241.md`.

## 0.23.12 — Trust Rotation & Revocation

- Root-signed, epoch-versioned trust policy with active/verify-only/revoked delegated signing roles across Prestarter, component updates and game manifests; no mutable URL can supply a new root of trust.
- Two independently signed component-set envelopes for upgrading legacy clients and enforcing new policy v2; metadata/signatures bind epoch, signer ID, policy digest and exact manifest bytes.
- Durable anti-rollback trust watermark and expiration checks; game API signing and Desktop launch paths accept only independently root-authorized signers; release v2 `verify-only` is time-bounded.
- See `docs/releases/0.23.12-trust-rotation-revocation.md` for signing process, migration limitations and release gates. This implementation is not TUF-compatible and Rust/OS E2E certification remains outstanding.

## 0.23.11 — Release Generations & Anti-rollback

- Component-set Ed25519-signed `securityGeneration` with replay/equivocation rejection and persistent verified high-watermark; updater recovery reconciles installed components before accepting a higher generation.
- Game `gameReleaseGeneration` tracked independently in signed manifests, installation, and launch. Historical content can be re-authorized only as a newly signed release with `rollbackSource` proof.
- Durable server-side package signing/publication and administrative rollback updated; ordinary client transaction journal recovery remains available after interrupted installs.
- Windows component-state migration and updater-helper validation hardened. See `docs/releases/0.23.11-release-generations-anti-rollback.md`.

## 0.23.6 — Filesystem & Platform Hardening (D06)

## [0.23.9] — Native Installers & Branded Bundles

- Implement a Java-free native install/verify/repair/uninstall lifecycle connected to the real Prestarter.
- Bind branding and per-OS/arch Prestarter hashes inside the signed Ed25519 bootstrap payload.
- Add Windows single-file installers, Linux .deb, macOS signed .pkg build paths and protected release signing.
- Preserve profile data on uninstall, retain offline sources for repair and add negative trust/integrity tests.


- Replaced vulnerable Windows unlink-old/rename-new live-file switches with atomic `ReplaceFileW` for managed files, recovery and release state slots; locked files fail without a missing-live-file window.
- Refused Windows device/ADS names, invalid trailing names, case and file/directory collisions, symlinks/junctions/reparse points, readonly files and unwritable parents before switching or restoring a release.
- Added stage/rollback disk-space preflight with overflow-safe calculations, durable copy cleanup, transaction-preserving ENOSPC handling, protection against overwriting previously untracked player files and negative Rust tests for mixed-file recovery and Windows sharing violations.
- See `docs/releases/0.23.6-filesystem-platform-hardening.md`. No claim of compiled/binary production certification without multi-OS Rust/FS E2E.

## 0.23.5 — Transactional Client Release (D05)

- Desktop, Repair, durable jobs and CLI sync now stage complete signed file sets under an isolated release work directory, use the existing network scheduler and shared SHA-256 cache, and verify the staged set before switching.
- Durable write-ahead switch journal, OS-wide commit lock, alternating active-release pointer, immutable checked backups and a last-known-good record enable rollback/recovery prior to launch, including interrupted explicit rollbacks.
- Retire only paths registered in the previous active release; never enumerate/delete unregistered files, saves, config, logs or other player data.
- Running Minecraft processes hold a shared release lease: updates/rollback cannot replace active game files. Desktop and CLI expose explicit release rollback/recovery, with tests for signed full-set switching, unregistered file preservation, interrupted commit and rollback. Rust/OS E2E verification is required for GA.

## 0.23.4 — Content-addressed Cache & Mirrors (D04)

- Desktop и Repair используют общий межпрофильный SHA-256 cache NeverRuntime: строгая проверка перед каждым чтением, атомарное сохранение и независимые копии вместо hardlinks.
- Межпоточная и межпроцессная блокировка одного SHA-256 предотвращает параллельную повторную загрузку и публикацию одного объекта.
- В подписанном manifest доступны fallback `files[].mirrors`; основной CDN и зеркала не могут изменить ожидаемый SHA-256, при отказе меняется HTTP-источник с соблюдением per-host квот.
- Добавлены счётчики `cacheHits`/`bytesReused` и фактических сетевых байтов в Runtime и Desktop.
- Добавлены тесты межпрофильной дедупликации, повреждённого кеша, подмены CDN и офлайн-восстановления из кеша. Rust тесты должны быть собраны/запущены в CI перед релизом.

## 0.23.3 — Network Resilience & Durable Jobs (D03)

- HTTP: bounded retries for 408/429/5xx and transient request/body errors, jittered exponential backoff, Retry-After seconds and RFC IMF-fixdate, connect/request/read timeouts.
- Real pause/cancel interrupts active network reads and retry timers while retaining fsynced verifiable partials; resume reopens verified Range/If-Range transfers.
- Alternating, restart-safe signed-manifest operation journals for Desktop/Repair; startup auto-recovery for interrupted operations, manual recovery for paused operations, and current pinned-key verification rather than trusting journal-provided keys.
- Tauri control and restore commands plus Desktop buttons; unit and local HTTP integration tests. Rust compiler / OS E2E verification remains required.

## 0.23.2 — HTTP Resume & Integrity (D02)

- Real Desktop/Repair NeverRuntime downloads preserve verifiable partial bytes and strong ETag metadata in the reserved `.neverlauncher/downloads` directory and resume with HTTP Range/If-Range after interruption or process restart.
- Strict 206 Content-Range/ETag/length validation and HTTP 200/416 fallback avoid mixing server object revisions. Files are activated only after full signed SHA-256/size verification; corrupted cache/parts are discarded.
- Added restart, ETag-change, malformed 206, HTTP 416 and invalid SHA-256 integration tests backed by a local HTTP server. Rust build and platform E2E must be run before certification.

## 0.23.1 — Shared Download Scheduler (D01)

- NeverRuntime: actual bounded, priority-aware streaming download scheduler replaces the sequential file loop. At most six concurrent transfers across operations and three per HTTP host; dispatcher skips temporarily saturated hosts without starving other mirrors/hosts. Connection redirects are refused so host admission cannot be bypassed.
- Desktop/Repair/CLI: existing signed-manifest download and repair operations use the same engine. Individual failures are collected without aborting unrelated transfers; SHA-256, expected size, safe paths, permission handling and atomic file replacement remain mandatory.
- Backpressure: bounded active workers and awaited streaming disk writes (64-KiB write slices); response bodies are not buffered as whole files. Early rejects for overlong declared/actual responses.
- Desktop: Tauri `neverlauncher-download-progress` events provide live per-operation queue, active/finished/failed counters, transferred bytes and file identity. React download panel offers explicit download and repair actions with progress displays and disabled duplicate buttons.
- Tests: local HTTP integration tests cover real overlap, global/per-host concurrency, independent failure handling, disk results, progress snapshots, priorities, and shared permits across two concurrent operations.
- Scope: D01 only. HTTP Range resume, persisted download queue and cache/mirror fallback are scheduled for later 0.23.x milestones, not claimed by 0.23.1.

## 0.23.0 — Client Profiles & Build Workspaces release certification

- Hardened workspace persistence: PostgreSQL duplicate-create conflicts are detected atomically, and both repositories reject mutation of pinned build settings, illegal transitions and release-package reservation changes.
- Protected in-progress release materialization from re-upload or restage after package reservation.
- Added Gravit preview-to-commit HTTP E2E, race-tested workspace CAS cases and real PostgreSQL atomic-import/concurrent-update coverage.
- Added fail-closed exact-commit Profile/Workspace certification with explicit per-test PASS evidence, wired to production release candidate gating and release bundle generation.
- Updated canonical version metadata and published upgrade, rollback and GA qualification instructions. The source change is not a signed GA release; distribution requires all platform E2E and signing evidence.

## 0.22.10 — Gravit Static ClientProfile Import

- Implemented deterministic per-field `mapped` / `transformed` / `manual` / `blocked` conversion with strict JSON/path validation, source SHA-256 and fail-closed behavior for unsupported Gravit classloaders, optional actions, flags and security rules.
- Converted typed Java/RAM, ordered arguments, explicit signed-JAR classpath and conservative file include/exclude/verify semantics into Never Build Workspace settings; user-owned files cannot be silently overwritten or cleaned.
- Added RBAC-protected Admin inspection/import routes, interactive field report + JSON download, and atomic profile revision 1 + private workspace creation in PostgreSQL or MemoryRepository.
- No foreign secrets, profile owner privileges, published releases or signing keys are imported; newly imported workspaces must stage, validate, build and publish through the existing pipeline.
- Added negative/positive converter tests and repository conflict/concurrency regression tests. Production certification remains conditional on full API/Admin builds, PostgreSQL transaction E2E and Minecraft launch tests.

## 0.22.6 — Build Workspaces

- Implemented durable owner-scoped build workspaces with PostgreSQL revision CAS and memory parity.
- Browser directory import now stores content-addressed source blobs in private storage and verifies full SHA-256/size on scan and build.
- Added base-version file diff, exact staged selection, deterministic build digests covering profile revision, inputs and tool versions.
- Materializes validated files into real v2 release packages using existing storage, repository and manifest workflows; partial builds can resume safely.
- Connected Admin Release Workspace to directory import, stage, validate and build operations while retaining existing Ed25519 signing, integrity, runtime evidence and durable publication gates.
- Added migration 0059 to both API and CLI catalogs; existing signed public releases remain unchanged.
- Qualification remains conditional on full API/Admin build, live PostgreSQL and end-to-end publication tests.

## 0.22.5 — Profile Management

- Implemented revision-aware profile clone, portable v2 JSON export/import with digest verification, immutable revision diffs and built-in loader/profile presets.
- Added atomic create-only profile persistence in PostgreSQL and MemoryRepository to reject conflicting IDs without overwriting existing profiles or revision history.
- Added Admin profile management interface, audited and RBAC-protected operations, OpenAPI schema updates and regression tests.
- Fixed a corrupted demo MemoryRepository constructor in the supplied 0.22.4 source; the seeded published manifest now pins the initialized vanilla snapshot.
- Preserved existing signed v1/v2 releases; no database migration or silent re-signing.

## 0.22.4 — File Ownership and Safe Repair

- Enforced signed v2 `files[].ownership` and `fileRules[]` in API publication, NeverRuntime file operations, Desktop cleanup and CLI updater.
- Protected saves, screenshots, resource packs and user settings; optional/generated/user-owned paths are not silently overwritten or deleted.
- CLI client cleanup/rollback preserves untracked mods and only operates on tracked installed files; real integration tests cover install/repair/cleanup/rollback.
- Introduced additive SQL migration 0058 and persisted ownership metadata in production `files` rows without re-signing historical releases.
- Added safety checks for path rules, symlinks, download SHA-256, and pinned-key verification before cleanup; see `docs/runtime/file-ownership-0224.md`.
- Release qualification: full API integration, live PostgreSQL migrations, Rust and multi-OS E2E remain to be verified in their respective CI environments.

## 0.22.3 — Runtime Constraints

- Added runtime Java major range (min/recommended/max), typed memory enforcement and strict JVM argument validation to signed v2 manifests.
- Implemented signed ordered classpath/modulepath and Java mainModule execution in NeverRuntime without shell invocation.
- Prevented JVM heap/path/agent overrides and unsafe inherited Java environment variables for v2; preserved v1 signature compatibility.
- Applied checks to editable API manifests, publication validation and resolved runtime launches; added positive/negative model and runtime unit tests.
- Production certification still requires full integration and Rust builds; see `docs/runtime/runtime-constraints-0223.md`.

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

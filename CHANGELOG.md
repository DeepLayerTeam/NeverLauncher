## [0.21.0] - 2026-10-06

- Shipped NeverExtensions GA with frozen Extension Package v1, Manifest v2, Host Protocol v1 and Extension API v1. New registry publications must use `api: 1.0`; existing signed 0.20 packages with `api: 3.7` remain runnable through an explicit compatibility alias without signature mutation.
- Added production GA startup reconciliation across install lockfiles, registry package identity, publisher/key trust, quarantine and emergency-disable state, permissions, dependencies and conflicts. Invalid enabled installs fail closed into persistent emergency-disable and are audited.
- Completed Extension API v1 negotiation across Backend, Admin, Desktop and CLI hosts plus all SDKs. Fixed the Desktop host context envelope so the Desktop SDK receives the negotiated runtime context instead of `null`.
- Added a real 0.20→0.21 extension source upgrader (`nl extension upgrade-source`) with atomic writes, SDK reference migration and mandatory rebuild/re-sign boundary for signed packages. Added durable GA contract migration/invariants.
- Added NeverExtensions GA documentation, Linux/Windows/macOS certification workflow, evidence aggregation, public compatibility matrix generation and tamper-evident certification artifact generation.

## [0.20.12] - 2026-10-06

- Added production NeverExtensions publisher trust and revocation: persistent strict/audit registry policy, publisher allow-lists, irreversible key revocation, fail-closed lifecycle verification and immediate runtime enforcement for active registry extensions that lose trust.
- Added persistent forensic extension quarantine. Rejected/malicious uploads and artifacts signed by revoked keys are retained in configured storage, blocked from lifecycle/Host execution and require an explicit fresh-auth administrative release.
- Made crash-loop protection survive Backend restarts: the Extension Host now invokes a durable kill-switch callback, persists an emergency disable, disables lifecycle state and refuses later start/enable attempts until an administrator explicitly clears the incident.
- Added Backend Safe Mode `--no-extensions`; event workers, extension process hosts, Admin/Desktop extension UI/RPC, CLI-extension invocation and lifecycle enable/start are suppressed while core recovery/trust administration stays available.
- Added trust/recovery Admin API and `nl extension trust|quarantine|emergency|recovery ...`. Recovery export/import preserves publisher identities, public keys/revocation, trust policy, quarantine, emergency disables and pins; backup/restore adds a canonical SHA-256 envelope and re-verifies registry artifacts through the normal lifecycle before restoring installations. Private signing keys and extension secret plaintext are excluded.
- Added migration `0048_neverextensions_trust_recovery_certification_02012`, malicious `.nlext` regression tests (traversal, absolute paths, Windows aliases, symlink and case collisions), recovery/fail-closed trust tests, and a Linux/Windows/macOS evidence-driven CI certification workflow that publishes the public compatibility matrix only after all required runner checks pass.

## [0.20.11] - 2026-10-06

- Added a production SemVer dependency resolver with exact, wildcard, comparator, caret, tilde and OR constraints, required/optional dependencies, bidirectional conflicts, graph cycle detection and dependency-first ordering.
- Added compatibility resolution across NeverLauncher version, Extension API version, operating system and architecture, with stable/beta/dev channel fallback and backtracking when a newer candidate produces an unsatisfied dependency or conflict.
- Added persistent global/project exact version pins and migration `0047_neverextensions_dependencies_updates_02011`; pins are enforced both during resolution and again immediately before activation.
- Added durable multi-extension update transactions with cross-replica scope leases, stale-plan/artifact checks, permission preflight for updates and auto-installed dependencies, dependency-first staged application and transaction journals with crash-safe `inFlight` fencing/recovery.
- Added automatic compensation rollback in reverse dependency order when install/update, Host startup or health verification fails; previously enabled extension processes are restored from the pre-transaction snapshots.
- Routed the legacy single-extension update API through the same dependency-aware transaction engine so dependency/conflict/pin policy cannot be bypassed. Added update plan/apply/transaction/pin REST APIs, `nl extension updates ...`, registry API compatibility metadata and the mandatory 0.20.11 production gate.

## [0.20.10] - 2026-10-06

- Added the real NeverExtensions SDK distribution under `sdk/`: Backend Go, CLI Go, Admin TypeScript, Desktop TypeScript and Desktop Rust SDKs with generated protocol/OpenAPI metadata.
- Added deterministic SDK type generation from `sdk/api/extension-host-protocol.json` plus canonical NeverExtensions OpenAPI operations; CI regenerates the files and rejects drift.
- Added production developer commands `nl extension init|build|test|dev`. `init` supports single or multi-target packages, `build` produces the executable payload entrypoints consumed by the Extension Host, and `test` validates, builds, runs target tests, packs and verifies a real `.nlext`.
- Added an authenticated loopback local dev Host Protocol with explicit deny-by-default `--grant`, fixture-backed capability responses, sanitized child environment, real hello/heartbeat/log handling and isolated Admin/Desktop sandbox previews.
- Fixed the historical Backend SDK scaffold mismatch: manifests now point to `backend/bin/extension-backend` rather than Go source, so generated Backend extensions are directly runnable by the production supervisor after build.
- Added runnable Backend, CLI, Admin and Desktop example extensions plus SDK unit/E2E coverage and the mandatory 0.20.10 production gate. No database migration is required.

## [0.20.9] - 2026-10-06

- Added production Desktop extensions: enabled immutable `desktop` targets are exposed through the authenticated Desktop API, loaded only from the active payload and rendered in opaque-origin `sandbox="allow-scripts"` iframes with the same restrictive no-network CSP used by the Admin host.
- Added typed `neverextensions.desktop-rpc.v1` postMessage bridging with source/in-flight validation. Backend RPC re-checks extension capability grants plus the current user's project access; the iframe never receives the Desktop access token or raw Tauri `invoke`.
- Added a deliberately narrow Tauri parent bridge gated by the separate `desktop:bridge` capability: extensions may query platform metadata and request opening the already configured game directory, but cannot supply arbitrary filesystem paths or invoke arbitrary native commands.
- Added production CLI extensions through the authenticated Extension Host Protocol. `nl x <namespace> <command>` resolves enabled immutable CLI contributions, launches the declared executable as a short-lived supervised process, requires authenticated Host `hello`, sanitizes its environment, enforces process/RSS/output/time bounds and keeps capability access deny-by-default.
- Added `nl extension cli list|run|completion`, Bash/Zsh/Fish completion generation and runnable Desktop/CLI SDK scaffolds. A single `.nlext` is now regression-tested with `backend`, `admin`, `desktop` and `cli` targets together.
- Added canonical Desktop/CLI contribution validation, `desktop:contribute`, `desktop:bridge` and `cli:contribute` capability catalog entries, Desktop RPC schema/OpenAPI coverage, subprocess/sandbox/multi-target tests and the mandatory 0.20.9 production gate. No database migration is required.

## [0.20.8] - 2026-10-06

- Added the production NeverExtensions Admin Extension Host with declarative pages, navigation, dashboard widgets and actions backed by enabled immutable extension versions.
- Admin executable UI is loaded only from the active extension payload and rendered in opaque-origin `sandbox="allow-scripts"` iframes; no extension JavaScript is imported into the NeverLauncher React bundle. Standalone Admin HTML receives a restrictive CSP with network, object, form and nested-frame access disabled.
- Added typed `neverextensions.admin-rpc.v1` postMessage/RPC bridging plus a TypeScript SDK. RPC requests are rebound to the current authenticated Admin session and require both the extension capability grant and the user/project authorization, preventing UI extensions from bypassing RBAC, Guard or Device Trust.
- Added the Admin Extension Manager with persistent install state, permission state, Backend Host runtime/health, errors and bounded recent logs plus Host start/stop/restart and enable/disable operations.
- Extended canonical extension manifests with validated Admin contributions; contributions require an `admin` target, explicit `ui:contribute` permission and a standalone `.html` entrypoint.
- Added Admin Host schema/OpenAPI coverage, traversal/symlink/CSP/manifest regression tests and the mandatory 0.20.8 production gate. No database migration is required.

## [0.20.7] - 2026-10-06

- Replaced manifest-implies-access with an explicit deny-by-default capability policy: extension manifests only request permissions, while effective access is the intersection of immutable-version requests and persisted global/project grants.
- Added migration `0046_neverextensions_capability_security_0207` with persistent permission grants and AES-256-GCM encrypted extension secrets; project-scoped grants/secrets are validated against real projects and secret plaintext is never returned by Admin list APIs or written to audit.
- Added grant/revoke, permission-state/diff and secret-management Admin APIs plus `nl extension capabilities|permissions|permission-grant|permission-revoke|secrets|secret-set|secret-delete`; critical writes require fresh MFA/phishing-resistant authentication.
- Made the Extension Host fail closed on policy/repository errors and re-check grants dynamically for privileged capabilities and event delivery; update preflight blocks activation when a candidate version adds permissions that have not been explicitly granted.
- Expanded the capability broker for project/release/storage/telemetry, secure outbound HTTPS, events and secrets; outbound HTTP uses public-IP DNS pinning, no proxy/redirects and bounded request/response/timeouts to prevent SSRF into loopback/private/link-local networks.
- Added privileged-call audit without secret/payload leakage, production configuration/OpenAPI coverage, migration/security/host regression tests and the mandatory 0.20.7 production gate.

## [0.20.6] - 2026-10-06

- Added the production typed NeverExtensions Event Bus with durable PostgreSQL event log, persistent subscriptions, per-subscription delivery state, ordering keys, idempotency keys, payload SHA-256 integrity and cryptographic lease fencing against stale worker ACKs.
- Added synchronous pre-mutation hooks with fail-closed per-hook timeouts and separate durable asynchronous delivery with lease recovery, exponential retry and persistent DLQ snapshots.
- Extended the authenticated loopback Extension Host Protocol with subscribe/unsubscribe/list and callback delivery using a separate per-process callback token; callback endpoints are restricted to numeric loopback origins and redirects are refused.
- Added permission-gated event subscriptions (`events:subscribe`, `events:sync` plus domain permissions), project-scope filtering and install-state-aware dispatch: disabled/uninstalled extensions retain their durable backlog without consuming retries, while crashes on one Backend replica do not globally disable subscriptions.
- Wired project, release, package, storage, ServerBridge and audit events into successful domain operations; sync hooks run only after normal HTTP authentication/authorization/Guard/Device Trust middleware and cannot obtain user bearer tokens, Guard/device credentials or Backend database/storage secrets.
- Added migration `0045_neverextensions_events_hooks_0206`, Admin event diagnostics/DLQ API, event envelope schema, production configuration, repository/worker/timeout/DLQ regression coverage and the mandatory 0.20.6 CI gate.

## [0.20.5] - 2026-10-05

- Added the production NeverExtensions Backend Extension Host: enabled backend targets execute as separately supervised OS processes rather than Go plugins or in-process code.
- Added a loopback-only authenticated Host Protocol with per-process 256-bit bearer tokens, mandatory identity-bound hello, heartbeats, structured logs and a permission-gated capability broker for project/release/storage access.
- Added process supervision with startup/stop/capability timeouts, crash detection, bounded automatic restart with crash-loop suppression, stdout/stderr capture and bounded in-memory log retention.
- Added Linux process-group supervision with parent-death signal, aggregate process-tree RSS/process-count enforcement and Backend `PR_SET_DUMPABLE=0` memory hardening; extension child environments are allowlisted and never inherit Backend DB/auth/signing/storage secrets.
- Integrated Host execution with install lifecycle compensation: enable rolls back to disabled on startup failure, update rolls payload/state back when the new process cannot activate, and disable/update/rollback/uninstall stop running processes before filesystem swaps.
- Added Host health/log/start/stop/restart Admin API, `nl extension host ...`, Admin runtime controls, production configuration, OpenAPI coverage, real subprocess/heartbeat/crash-loop tests and the mandatory 0.20.5 CI gate. No database migration is required.

## [0.20.4] - 2026-10-05

- Added production NeverExtensions install lifecycle with install, enable, disable, update, rollback and uninstall for global and project scopes, persisted desired/current version and state, package identities and monotonic generations.
- Added migration `0044_neverextensions_install_lifecycle_0204` and append-only lifecycle revisions; PostgreSQL transitions use SERIALIZABLE transactions, advisory locks, row locks and generation compare-and-swap to prevent lost updates.
- Added verified staged activation under `NEVERLAUNCHER_EXTENSION_ROOT`: registry artifacts are re-read from storage, SHA-256/package identity/Ed25519 verified, extracted into staging, atomically swapped into `current`, and previous payloads retained as bounded generation backups.
- Added failure compensation across filesystem and repository state, persistent `neverextensions.lock.json`, exclusive per-install lifecycle lock, rollback from retained backups and lockfile/state consistency diagnostics.
- Added authenticated REST lifecycle API, top-level `nl extension installed|status|install|enable|disable|update|rollback|uninstall`, and Admin Registry lifecycle controls with global/project scope selection.
- Added `.nlext` payload extraction integrity checks, lifecycle repository/CLI/migration regression coverage, production configuration and mandatory 0.20.4 CI gate.

## [0.20.3] - 2026-10-05

- Added the production private/local NeverExtensions Registry with trusted publishers and Ed25519 keys, immutable extension/version publications, compatibility metadata, content-addressed artifacts, movable channels and irreversible yank state.
- Added strict server-side `.nlext` inspection/verification and verified-only installation: registry publish accepts only a signature trusted for the manifest publisher, while install re-reads storage bytes and repeats SHA-256/package-identity/Ed25519 verification before persisting install state.
- Added authenticated Registry API for publisher/key management, search/list/details, multipart publish, artifact download, channel movement, yank and install, backed by PostgreSQL migration `0043_neverextensions_registry_0203` and serializable repository transactions.
- Added `nl extension registry publishers|publisher-add|key-add|keys|search|list|show|publish|yank|channel-set|pull|install`, including download SHA-256 verification, plus a functional Admin Registry UI.
- Fixed `.nlext` SBOM verification so immutable packages created by NeverLauncher CLI 0.20.2 remain verifiable by later registry/server versions without weakening package identity or signature checks.
- Added Registry repository/package/CLI/API regression coverage, OpenAPI multipart/binary contract support, production table checks and a mandatory 0.20.3 CI gate.

## [0.20.2] - 2026-10-05

- Added the production `.nlext` extension package format with deterministic ZIP layout, canonical manifest embedding, payload hashing, `checksums.sha256`, SPDX 2.3 SBOM and a content-derived immutable package identity.
- Added `nl extension pack|sign|verify|inspect`, including deterministic Ed25519 signatures, external trust-key verification and optional unsigned integrity verification.
- Added fail-closed package validation for path traversal, Windows-unsafe paths, symlinks/special files, case-colliding duplicate entries, missing target entrypoints, archive size/compression limits and unexpected package files.
- Added canonical package/signature schemas, reproducible-build support through `SOURCE_DATE_EPOCH`, cross-platform CLI compilation coverage and a mandatory 0.20.2 production CI gate.

## [0.20.1] - 2026-10-05

- Added the canonical NeverExtensions Core model and `neverlauncher-extension.json` schema 2.0 with multi-target manifests, permissions, hooks and dependencies.
- Added PostgreSQL migration `0042_neverextensions_core_0201` with normalized `extensions`, `extension_versions`, `extension_permissions`, `extension_dependencies` and `extension_installs` tables, constraints and indexes.
- Added a real PostgreSQL and in-memory extension repository with immutable `(extensionId, version)` manifests, deterministic SHA-256 identity, publisher takeover protection and persisted install selection.
- Added authenticated Admin API for registering and reading canonical extension versions through the production repository layer.
- Added `nl extension template|validate|import-legacy`; `nl sdk init` now creates `neverlauncher-extension.json`, while legacy `neverlauncher-plugin.json` remains importable with an explicit publisher.
- Removed nonexistent `registry_entries` and `desktop_packages` from `productionTables()` and replaced them with the actual NeverExtensions Core tables.

## [0.20.0] - 2026-10-05

- Promoted ServerBridge 3 to GA with a frozen Protocol v3 feature set/digest; Protocol v2 remains Backend compatibility/deprecation-only and emits explicit migration metadata.
- Added the production `nl server-bridge migrate-v3` path with GA Backend preflight, certified transactional artifact upgrade, dry-run/rollback compatibility, node-identity preservation and durable migration receipt.
- Added GA certification schema 1.1 and release-allowlist enforcement across certifier, release verification and provisioning for all 14 ServerBridge artifacts.
- Added one authenticated ServerBridge operator overview API combining node/runtime state, telemetry, topology, control history and audit, plus a dedicated Admin UI overview.
- Added database migration `0041_serverbridge3_ga_0200`, completed the public 14-target compatibility matrix and documented the v2→v3 production rollout.

## [0.19.12] - 2026-10-05

- Added one canonical ServerBridge Protocol v3 signing domain for capability negotiation, node requests, ordered events and Backend control commands, with node fingerprint, runtime instance and identity/runtime epoch binding.
- Added fail-closed capability downgrade protection: the 0.19.12 Bridge offers only Protocol v3 and requires the exact certified six-feature security profile/digest while the Backend retains compatibility for older fleet releases.
- Added signed Backend capability documents plus overlap active/previous Ed25519 trust, allowing zero-downtime control signing-key rotation without retaining removed keys as hidden authorization anchors.
- Added ServerBridge 3 schemaVersion 3.0 release allowlist/certification checks across Backend, CLI and certifier with exact security metadata and all 14 platform artifact hashes.
- Added runtime-bound command signatures and execution replay identity, v3 event signatures, signed node request runtime binding and migration of pending legacy event-journal entries into v3-signed records.
- Added adversarial security tests and an executable 14-target × 10-scenario E2E certification matrix covering tampered bridge/node/event/command, replayed event/command, runtime rebind, capability downgrade and online key rotation. No database migration is required.

## [0.19.11] - 2026-10-04

- Added production ServerBridge HA Control Plane with ordered multi-Backend endpoint failover, endpoint cooldown and terminal fail-closed handling for authentication/authorization responses.
- Added durable channel resumption using per-runtime `channelId` plus monotonic `deliverySequence`; reconnect to another API replica resumes after the last locally acknowledged sequence.
- Added PostgreSQL distributed command ownership with `FOR UPDATE SKIP LOCKED`, `lease_owner`/`lease_token` fencing and idempotent terminal ACKs that can be replayed safely on another Backend replica.
- Added Redis command fencing and channel presence as a second coordination layer; production HA refuses control delivery/ACK when the required Redis coordinator is unavailable.
- Preserved exactly-once side-effect behavior through the Bridge execution journal: delivery leases/timestamps can rotate while the stable command execution digest remains unchanged.
- Added migration `0040_serverbridge_ha_control_plane_01911`, multi-replica PostgreSQL integration coverage, Redis fencing tests, 14 platform HA endpoint config examples and mandatory CI/preflight production gate.

## [0.19.10] - 2026-10-04

- Added production ServerBridge Host supervisor with `configure|start|run|stop|restart|status|logs`, detached lifecycle management and exclusive per-server lock.
- Added real JVM process supervision: persisted supervisor/Minecraft PID state, exit-code and crash detection, bounded `never|on-failure|always` restart policies, configurable restart backoff and graceful-stop timeout.
- Added Java/JRE selection through explicit path, `NEVERLAUNCHER_SERVERBRIDGE_JAVA`, `JAVA_HOME` and PATH with `java -version` validation; added repeated JVM/server argument support.
- Added launch support for normal `java -jar` platforms plus native modern Forge/NeoForge `@unix_args.txt` / `@win_args.txt` argument files without replacing Minecraft main class or patching authlib/core files.
- Added separate stdout/stderr logs, a timestamped combined stream, tail/follow CLI, Unix process-group signal handling, Windows detached process-group support, regression tests and mandatory CI/preflight gate. No database migration is required.

## [0.19.9] - 2026-10-04

- Added production Zero-Patch Provisioning CLI: `nl server-bridge detect|install|enroll|status|upgrade|rollback` with automatic certified-platform detection and fail-closed hybrid-core rejection.
- Installer selects the exact platform artifact, validates its platform descriptor/class plus ServerBridge 3 certification/SHA-256, performs atomic managed-file updates, creates Java-compatible local Ed25519 node identity and a public-only enrollment request, and never edits Minecraft/proxy core or authlib files.
- Added transaction journals/backups, `--dry-run`, automatic failure rollback and explicit rollback of install/upgrade operations; upgrades preserve node identity and refuse silent cross-platform replacement.
- Added enrollment against the existing administrative ServerBridge API with idempotent exact-identity handling, optional identity rotation, and local enrollment status persistence; `status` correlates local artifact/identity state with Backend node state when credentials are supplied.
- Fixed release verification so historical releases keep the 11-target cohort while 0.19.8+ requires the complete 14-target Universal Server Adapter cohort.
- Added 0.19.9 provisioning tests and mandatory CI/preflight production gate. No database migration is required for this release.

## [0.19.8] - 2026-10-04

- Added Universal Server Adapter capability profiles and runtime capability publication so platform behavior is selected by explicit capabilities instead of platform-name/`instanceof` inference.
- Added production Quilt, Sponge and Vanilla sidecar adapters. Quilt uses a server-only Quilt Loader artifact and login/event/control/telemetry hooks; Sponge uses the native asynchronous Auth gate and Sponge scheduler; Vanilla uses bounded local RCON plus log-tail integration without pretending to have a pre-login plugin gate.
- Expanded ServerBridge registration, runtime identity, artifact integrity allowlists, OpenAPI and PostgreSQL canonical kinds from 11 to 14 adapters with separate `quiltSha256`, `spongeSha256` and `vanillaSha256` namespaces.
- Added fail-closed hybrid-core policy and separate certification matrix: Mohist, Arclight, Magma, CatServer, Banner and Cardboard cannot inherit Bukkit/Fabric/Forge certification.
- Added migration `0039_universal_server_adapters_0198`, 14-target release certification/build rules and the 0.19.8 production gate.

## [0.19.7] - 2026-10-04

- Added production Player Session Integration 3 with a cryptographically random `sessionCorrelationId` spanning launcher join, proxy ownership and final backend admission.
- Added PostgreSQL authoritative player lifecycle and ordered transfer chain with runtime-bound source/target ownership, monotonic transfer sequence and mandatory trust/integrity recheck before transfer consumption.
- Added active-session clone prevention for Never/Minecraft credentials; a replacement correlation atomically invalidates the previous lifecycle and queues durable Control API disconnects to its proxy/backend nodes.
- Session/user/device revocation, permanent Device Trust/Guard failure and stale/replaced runtime maintenance now invalidate the complete correlated topology instead of only transient join/handoff rows.
- Added correlated player quit/kick event handling, migration `0038_serverbridge_player_session_integration3_0197`, Java runtime correlation registry, release certification requirements and the 0.19.7 production gate while preserving Protocol v2 rolling compatibility.

## [0.19.6] - 2026-10-04

- Added ServerBridge 3 Topology & Routing 2 with Ed25519-attested, runtime-bound route snapshots published on Protocol v3 heartbeats.
- Added realtime proxy route discovery filtered by heartbeat freshness, maintenance/drain state, health and effective player capacity including in-flight handoff reservations.
- Added handoff v3 source+target runtime/routing proof capture, target runtime revalidation at redemption, direct-backend route admission checks and immediate invalidation when a target becomes non-routable.
- Added automatic stale topology disable/purge, migration `0037_serverbridge_topology_routing2_0196`, OpenAPI route schemas, release certification requirements and the 0.19.6 CI production gate while retaining Protocol v2 rolling compatibility.

## [0.19.5] - 2026-10-03

- Added production ServerBridge 3 Backend→Bridge control channel with runtime-bound durable command leasing, signed node poll/ACK and dedicated Backend Ed25519 command signatures.
- Added native platform execution for kick, broadcast, whitelist/ban operations, save, maintenance/drain, graceful shutdown and allowlisted console commands; no OS shell execution is used.
- Added RBAC (`serverbridge:control` / `serverbridge:console`), mandatory idempotency keys, local at-most-once execution journal, reconnect/reload safety, full PostgreSQL audit transitions and bounded terminal-command retention.
- Added migration `0036_serverbridge_control_api_0195`, OpenAPI schemas/routes, release certification requirements, common Java runtime tests and the 0.19.5 CI production gate.

## [0.19.4] - 2026-10-03

- Added a production Protocol v3 ordered Server Event Stream with per-event Ed25519 signatures, runtime-bound monotonic sequence numbers, contiguous ACKs, batch delivery and signed request nonce replay protection.
- Added a bounded durable bridge journal with reconnect/plugin-reload resume, idempotent resend and clean/unclean runtime markers used to publish crash evidence after an unexpected JVM termination.
- Added real platform event hooks for server lifecycle/error, player login/join/quit/kick, world lifecycle and proxy connect/switch across the supported Bukkit/proxy/Fabric/Forge/NeoForge families.
- Added PostgreSQL migration `0035_serverbridge_event_stream_0194`: event rows, per-runtime ACK cursors and transactional insertion into the common `audit_events` trail. Conflicting replay and sequence gaps fail closed.
- Added 30-day bounded raw event retention, OpenAPI event/ACK schemas, repository/API tests, PostgreSQL integration coverage, release certification requirements and the 0.19.4 CI production gate.

## [0.19.3] - 2026-10-03

### ServerBridge 3 — Server Telemetry
- Added signed Protocol v3 telemetry bound to the verified Ed25519 runtime identity and negotiated through `telemetry.server-v1`.
- Added bounded JVM telemetry for heap/non-heap memory, GC totals/deltas, thread counts and derived tick health.
- Added platform-safe TPS/MSPT, player capacity, worlds/dimensions and bounded chunk/entity sampling across Bukkit/Paper/Purpur/Folia, Fabric, Forge, NeoForge, Velocity, BungeeCord and Waterfall.
- Platform adapters never enumerate game state from the heartbeat HTTP thread; unsupported or budget-exceeded counters remain absent instead of being reported as false zeroes.
- Added PostgreSQL migration `0034_serverbridge_telemetry_0193`, latest telemetry on node state, runtime-bound history, per-node history cap and seven-day HA retention.
- Added strict telemetry validation, OpenAPI schema, release certification classes, regression tests and the 0.19.3 telemetry CI gate.

## [0.19.2] - 2026-10-03

### ServerBridge 3 — Node Discovery & Runtime Identity
- Added real platform discovery for Minecraft version, Java runtime, platform/loader version, server brand, hostname/node name and bridge plugin/mod capabilities across all eleven ServerBridge artifacts.
- Added deterministic per-JVM `runtimeId` derived from node identity + JVM start time + PID + hostname and an independent Ed25519 runtime attestation signed by the registered node key.
- Backend now independently recomputes runtime IDs, verifies runtime signatures, rejects mutated discovery facts and persists current runtime metadata plus runtime instance history in PostgreSQL.
- Added runtime epochs and restart/replacement detection: stale predecessor -> restart; overlapping fresh predecessor -> replacement; same runtime ID must retain the same signed identity digest.
- Added Protocol v3 runtime feature negotiation (`runtime.node-discovery-v1`, `security.runtime-identity-ed25519`) with 0.19.1 v3 and 0.19.0 v2 rolling compatibility.
- Added migration `0033_serverbridge_runtime_identity_0192`, OpenAPI runtime schema, release-certification checks for runtime classes, and executable runtime identity/transition tests.

## [0.19.1] - 2026-10-03

### ServerBridge 3
- Added production Protocol v3 wire contracts for heartbeat, validate-join and proxy handoff while retaining Protocol v2 for rolling upgrades.
- Added public capability negotiation with protocol/feature selection and fail-closed v3 required feature validation.
- Bridge runtimes now negotiate v3, cache the negotiated result, attach feature flags to v3 requests, and downgrade to v2 only when an older Backend returns 404 for the capability route.
- PostgreSQL now persists each node's negotiated v2/v3 protocol and issues one-time join tickets using the target node protocol.
- Release certification, public matrix, diagnostics, OpenAPI and production deployment checks are updated for ServerBridge 3.

## 0.19.0 — NeverGuard Windows Protection GA


- Windows protection переведён из RC в GA отдельным machine-verifiable `WINDOWS_PROTECTION_GA_CERTIFICATE.json`: GA строится только поверх успешно перепроверенного `WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json`, exact adversarial cohort из 55 Windows/JVM executions и тех же Authenticode/RFC3161 x64/ARM64 bytes.
- GA boundary фиксирует `user-mode + aggressive + fail-closed`, полный capability set Sensor/Module Guard/Hook Engine/Memory/Thread+Process/Debug/JVM-aware/Continuous Guard/Attestation v2 и deterministic `boundarySha256`/`certificateId`.
- Production verifier открывает x64/ARM64 package manifests и ZIP и fail-closed отклоняет `.sys`/driver payload: 0.19.0 сертифицирует именно user-mode protection без kernel driver.
- Production Candidate, Production Delivery Release, `RELEASE_MANIFEST.json`, `publish-check`, release CLI, build script и GitHub production workflow теперь обязаны включать/проверять GA certificate. Server-side continuous Attestation v2 + one-time ServerBridge join ticket остаются обязательной production границей.
- Добавлены targeted Go tests и обязательный `neverguard-windows-protection-ga-0190.py` gate в CI/preflight/repository-policy.

## 0.18.12 — Windows Protection RC

- Добавлен production `WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json`, который строится не из ручных флагов, а из проверенного `WINDOWS_ADVERSARIAL_CERTIFICATE.json`, production Authenticode/RFC3161 evidence и фактических x64/ARM64 Windows release bytes.
- RC certificate привязан к exact source commit/repository/run-id, 55 live adversarial/compatibility executions на Java `8/16/17/21/25`, aggressive protection profile, обязательному capability set и SHA-256 каждого CLI/Desktop/Guard/Sensor/Runtime/package artifact.
- `nl release windows-protection-verify` и `release publish-check` повторно вычисляют Windows protection boundary и fail-closed отклоняют подменённый adversarial certificate, package manifest, signed binary, capability cohort или `certificateId`.
- `PRODUCTION_RELEASE_CANDIDATE.json` включает Windows Protection RC в exact pre-sign cohort, а `PRODUCTION_DELIVERY_RELEASE.json` дополнительно якорит и RC certificate, и adversarial certificate в stable GA boundary.
- Production workflow скачивает exact-commit adversarial certificate из того же GitHub Actions run, передаёт его в `build-release.sh`, требует RC certificate в release bundle и проверяет соответствующие `RELEASE_MANIFEST.json` hashes. Добавлены Go tests и обязательные 0.18.12 preflight/repository-policy/CI gates.

## 0.18.11 — Windows Adversarial CI

- Добавлен исполняемый `scripts/guard_ci/windows_adversarial.py`: для каждой сертифицированной Java `8/16/17/21/25` он запускает 11 реальных Windows/JVM сценариев как отдельные `cargo test` процессы и фиксирует exit status, timeout, SHA-256 stdout/stderr и SHA-256 всех Sensor/adversarial fixture binaries.
- Compatibility-positive набор проверяет раннюю загрузку Sensor, trusted native module lifecycle, Continuous Guard cross-check, Job-bound process tree и штатный HotSpot JIT без false positive. Adversarial-negative набор проверяет unsigned DLL вне trusted roots, executable code-page drift, private executable thread start, startup instrumentation/JDWP, live debugger attach и foreign executable allocation.
- Результат каждой JVM привязан к exact repository/commit/run-id и получает собственный `evidenceRootSha256`. Aggregate job требует все пять Java majors и exact scenario set; отсутствие/подмена одного результата или digest делает certification fail-closed.
- Добавлен machine-verifiable `WINDOWS_ADVERSARIAL_CERTIFICATE.json`: 55 обязательных live scenario executions, Java evidence roots, общий evidence root и invariants `allCompatibilityScenariosPassed`/`allAdversarialScenariosDetected`.
- Узкая JVM-aware matrix 0.18.8 заменена полноценным Windows adversarial matrix; validator имеет отдельные unit/regression tests и обязательные 0.18.11 offline/preflight/repository-policy gates.

## 0.18.10 — Attestation v2

- Добавлен post-launch `neverguard/windows-guard-attestation/v2`: Backend получает свежий continuous Windows evidence уже после запуска защищённой JVM, а не только pre-launch snapshot Guard/Desktop.
- Evidence v2 включает состояние Module Guard, Aggressive Hook Engine, Memory Integrity, Thread & Process Integrity, Debug & Instrumentation Guard, JVM-Aware Protection и Continuous Guard с heartbeat/cross-check counters, sequences и rolling chain hashes.
- Desktop подписывает Attestation v2 тем же hardware-bound P-256 device key; challenge, release, runtime PID, base attestation и continuous evidence cryptographically bound в один digest/signature payload.
- Backend проверяет freshness, component versions, все health/fail-closed indicators и digest parity, после чего выпускает 45-секундный одноразовый Continuous Guard join ticket. Windows ServerBridge join при включённой Guard policy требует этот ticket и связывает его с той же Never session, trusted device, launcher version и точными Guard/Desktop artifact hashes текущей integrity-verified Minecraft session.
- Post-launch failure теперь снова fail-closed: ошибка Attestation v2 или ServerBridge join останавливает уже поднятую JVM. Добавлены migration `0032`, Go/Rust tests и обязательные 0.18.10 offline/preflight/Windows CI gates.

## 0.18.9 — Continuous Guard

- Added an independent Sensor-side rolling SHA-256 transport chain over every authenticated Module Guard event packet. The parent recomputes the same chain from received bytes instead of trusting a digest supplied by Sensor.
- Added mandatory sixth startup proof `CONTINUOUS_READY`. `Agent_OnLoad` cannot complete until the parent verifies the pre-proof chain and returns an HMAC-bound Guard ACK covering Guard sequence, Sensor sequence and the post-proof chain root.
- Added one-second bidirectional Continuous Guard heartbeats. Sensor sends its previous chain root and last acknowledged Guard sequence; the parent verifies both, advances its chain, returns a domain-separated HMAC ACK, and Sensor enforces a bounded `PeekNamedPipe` receive timeout.
- Sequence drift, Guard ACK HMAC failure, chain mismatch, heartbeat loss or stream disconnect now fail closed and terminate the protected JVM. Runtime evidence exposes Sensor/Guard heartbeat counts, cross-check count, both sequences and current/last-cross-checked chain SHA-256 roots.
- Added real Windows JVM integration assertions for startup and repeated runtime cross-checks, plus mandatory 0.18.9 offline/preflight/repository-policy/CI gates.

## 0.18.8 — JVM-Aware Protection

- Добавлен production JVM-aware enforcement внутри `neverguard-sensor.dll`: Sensor до установки hook engine идентифицирует реально загруженный `jvm.dll`, читает Windows version resource и fail-closed допускает только сертифицированные Java major `8/16/17/21/25`.
- Aggressive Hook Engine теперь привязывает successful `VirtualAlloc`/`VirtualProtect` transitions к фактическому native call stack через `RtlCaptureStackBackTrace`. Executable `MEM_PRIVATE` переход считается штатным JIT/Code Cache только при наличии caller frame внутри неизменного диапазона `jvm.dll`; foreign/unknown provenance завершает runtime fail-closed.
- Existing Memory Integrity и Thread Integrity остаются независимыми слоями: `MEM_IMAGE` code-page drift по-прежнему ловится содержательным SHA-256 baseline, а private executable thread start — thread-origin monitor. JVM-aware слой анализирует именно происхождение executable private-memory transitions и не объявляет JIT immutable.
- `Agent_OnLoad` теперь требует пятый HMAC-аутентифицированный startup proof `JVM_AWARE_READY`; continuous `JVM_AWARE_HEARTBEAT/TAMPER` передают Java major, baseline private-executable coverage, JIT transition counter, jvm.dll path digest и state digest в `WindowsJvmAwareProtectionReport`.
- Добавлен adversarial native fixture, который после hook reconciliation выполняет `VirtualAlloc(PAGE_EXECUTE_READWRITE)` из собственного не-JVM native thread и обязан завершить JVM fail-closed. CI дополнен реальной Windows/Temurin matrix для Java `8/16/17/21/25` с JIT workload и foreign executable-memory regression.

## 0.18.7 — Debug & Instrumentation Guard

- Добавлен production Debug & Instrumentation Guard внутри `neverguard-sensor.dll`: каждые 250 мс Sensor проверяет `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` и независимые `NtQueryInformationProcess` indicators (`ProcessDebugPort`, `ProcessDebugObjectHandle`, `ProcessDebugFlags`). Любая активная user-mode debug boundary завершает JVM fail-closed.
- Windows JVM launch path теперь блокирует сторонние `-javaagent`, `-agentlib`, `-agentpath`, JDWP/`-Xdebug`, `StartAttachListener` и попытку отменить attach hardening; те же проверки применяются к `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` и `JDK_JAVA_OPTIONS`.
- NeverGuard принудительно добавляет `-XX:+DisableAttachMechanism`, а `Agent_OnLoad` не возвращает управление JVM до четвёртого HMAC-аутентифицированного startup proof `DEBUG_INSTRUMENTATION_READY`; subsequent heartbeat/tamper evidence входит в общий ordered Sensor stream.
- Runtime status дополнен `WindowsDebugInstrumentationReport` с debug indicators, check counters и `stateSha256`; fail-closed violation отражается одновременно в Debug Guard и общем Module Guard state.
- Добавлен adversarial Windows integration probe, который реально подключается к защищаемой JVM через `DebugActiveProcess`, обслуживает debug events и проверяет обязательное завершение runtime.

## 0.18.6 — Thread & Process Integrity

- Добавлен production Thread Integrity engine внутри `neverguard-sensor.dll`: каждые 500 мс Sensor перечисляет JVM threads через ToolHelp, получает фактический Win32 start address через `NtQueryInformationThread`, проверяет committed executable backing через `VirtualQuery` и допускает thread start только из `MEM_IMAGE`. Старт потока из executable private/mapped memory считается подозрительным runtime transition и завершает JVM fail-closed.
- Thread lifecycle допускает нормальные JVM/GC/compiler thread create/retire transitions, ведёт baseline/current/new/retired counters, `threadSetSha256` и `threadOriginSetSha256` без запрета штатной многопоточности JVM.
- Existing runtime Job Object стал непрерывной process-tree enforcement boundary: внешний NeverRuntime перечисляет descendants JVM, проверяет каждый живой PID через `IsProcessInJob` и отклоняет breakaway/escaped descendants. Состояние дерева фиксируется в `processTreeSha256`, transition count и descendant peak.
- `Agent_OnLoad` теперь требует третий HMAC-аутентифицированный startup proof `THREAD_PROCESS_READY` после `HOOK_READY` и `MEMORY_READY`; heartbeat/tamper evidence входит в общий ordered Sensor stream и `WindowsModuleGuardReport`.
- Добавлены реальные Windows JVM regressions: наблюдение дочернего `cmd.exe` внутри Job Object и adversarial native fixture, создающий поток с start address в `MEM_PRIVATE` executable memory, который обязан завершить runtime fail-closed.

## 0.18.5 — Memory Integrity

- Добавлен production `neverguard-sensor` Memory Integrity engine: continuous `VirtualQuery` executable-memory inventory внутри защищаемой JVM без cross-process memory primitives.
- Executable `MEM_IMAGE` regions получают SHA-256 baseline; последующие protection/content drift считаются runtime tampering и приводят к fail-closed завершению JVM.
- JVM JIT/dynamic `MEM_PRIVATE` code отделён от immutable image code: новые executable ranges допускаются только из startup baseline либо после реально наблюдаемого успешного `VirtualAlloc`/`VirtualProtect` transition через Aggressive Hook Engine.
- Добавлены bounded lock-free transition ring, overflow fail-closed, executable-map/code-set digests, RWX/dynamic counters и HMAC-защищённые `MEMORY_READY`/`MEMORY_HEARTBEAT`/`MEMORY_TAMPER` evidence events.
- `Agent_OnLoad` не возвращает управление JVM, пока parent не проверит authenticated `MEMORY_READY`; Memory Integrity evidence включён в `WindowsModuleGuardReport`.
- Добавлен Windows adversarial JVM integration fixture, который после baseline изменяет собственную executable image code page и проверяет обязательный fail-closed.

## 0.18.4 — Aggressive Hook Engine I

- Added a production in-process IAT interception engine inside `neverguard-sensor.dll` for the protected JVM/native boundary. The engine parses PE import tables with strict bounds checks and intercepts `LoadLibraryA/W`, `LoadLibraryExA/W`, `VirtualAlloc` and `VirtualProtect` only in non-system modules of the current protected process.
- Hook installation is transactional: IAT pages are made writable only for the pointer update, original protection is restored immediately and `FlushInstructionCache` is issued. A pre-existing target that does not resolve to the expected Windows export is treated as a conflict and fails closed instead of being overwritten.
- Sensor protocol v3 adds authenticated `HOOK_READY`, `HOOK_HEARTBEAT` and `HOOK_TAMPER` records. `Agent_OnLoad` cannot return until Hook Engine coverage is non-zero and the parent verifies the HMAC-bound readiness proof.
- The Sensor continuously re-enumerates newly loaded native modules, hooks eligible imports, verifies every recorded IAT slot, maintains a hook-set SHA-256 and restores its own hooks during orderly unload. Any integrity drift is emitted to the parent and aborts the protected runtime.
- Runtime status now exposes `WindowsHookEngineReport` with coverage, intercepted-call, integrity-check and violation evidence. Windows JVM integration tests require real hook coverage and a real intercepted loader/native call in addition to the existing Module Guard checks.

## 0.18.3 — Module Guard

- Replaced point-in-time-only JVM module visibility with a continuous Sensor stream driven by `LdrRegisterDllNotification`. The loader callback is allocation-free and writes fixed records into a preallocated atomic ring; a dedicated worker emits ordered HMAC-SHA-256 load/unload events and heartbeats over the authenticated Sensor pipe.
- `Agent_OnLoad` now stays fail-closed until the parent authenticates Sensor protocol v2, captures an external ToolHelp module baseline and returns an HMAC-bound Module Guard arm acknowledgement. Ring overflow, event MAC/sequence failure or heartbeat loss invalidates the runtime.
- Added parent-side module policy and continuous reconciliation: trusted Windows/Java/runtime roots are accepted, modules outside them require valid Authenticode, every accepted load is SHA-256 bound into a rolling event chain, and periodic external snapshots must exactly match the event-derived base/path set. Policy or snapshot drift terminates the JVM.
- Supervised runtime status now exposes live Module Guard evidence (baseline/current counts, load/unload/heartbeat counters, event-chain/module-set hashes and violations). Windows CI includes real Java probes that exercise an allowed DLL load and a fail-closed unsigned DLL outside trusted roots.

## 0.18.2 — NeverGuard Sensor

- Added a real Windows JVM native agent crate that builds `neverguard-sensor.dll` and exports `Agent_OnLoad`/`Agent_OnUnload`; JVM startup fails with `JNI_ERR` if its authenticated startup channel cannot be established.
- All Windows Java launch paths prepend a signed `-agentpath` sensor and require a PID-bound HMAC-SHA-256 proof from `Agent_OnLoad` before the runtime is accepted; failed/missing proof terminates the child JVM fail-closed.
- Production x64/ARM64 delivery now builds, architecture-checks, Authenticode/RFC3161-signs and packages the Sensor, verifies it before launch, includes it in component transactions/signing evidence, and requires it in publish/release gates.
- Added a real Windows/Temurin integration test that launches `java -version` through the existing suspended Job Object path and proves Sensor load before Java main, plus mandatory 0.18.2 preflight/repository-policy/CI gates and Sensor `clippy -D warnings`.

## 0.18.1 — Windows Protection Core II

- Reworked NeverGuard Windows process protection into an executable profile engine with `audit`, `compat` and default `aggressive` profiles. Each profile maps to real `SetProcessMitigationPolicy` requirements; NeverGuard immediately reads the applied state back with `GetProcessMitigationPolicy` and fails closed when a required bit is unavailable or not active.
- Added runtime Windows capability evidence for Dynamic Code, extension points, strict handle checks, image-load policy, child-process policy, CPU architecture and actual launcher Job Object membership. Capability evidence is authenticated over the existing HMAC IPC session and validated independently by Desktop before the Guard handle becomes ready.
- Added explicit profile propagation from Desktop to `neverguard.exe` (`--protection-profile`) with `NEVERGUARD_WINDOWS_PROTECTION_PROFILE` as the process-level selector. `audit` measures without requiring mitigation bits, `compat` keeps JVM-independent compatible Guard restrictions, and `aggressive` retains the full existing Guard mitigation set.
- Remote Guard Attestation remains fail-closed and is allowed only under `aggressive`; `audit`/`compat` cannot be presented as equivalent high-trust protection. Status now exposes Protection Core/capability-model/profile identity and rejects profile substitution.
- Added real Windows integration coverage for all three profiles, capability-drift/profile-substitution regressions, mandatory 0.18.1 offline/preflight/repository-policy gates, and Windows CI execution through Rust tests plus `clippy -D warnings`.

## 0.18.0 — Loader Compatibility GA

- Promoted Fabric, Quilt, Forge, NeoForge and the certified Forge legacy paths (1.7.10 and 1.12.2) from release-certificate RC to runtime-enforced GA. Production materializer parsers reject concrete Minecraft/loader combinations outside the exact certified support surface before loader upstream/install access; `latest-release` is rechecked after Mojang resolution.
- Added a single executable GA support policy shared by Fabric/Quilt and Forge/NeoForge materializers. The policy binds 163 unique loader/Minecraft lines to the exact certified Java major and install mode, including LaunchWrapper/FML legacy and processor-based modern installers.
- `LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json` is now `ga-certified` for 0.18.0 and binds the executable support-policy SHA-256, 163 support entries, legacy Forge versions, all 292/292 release targets and the existing immutable pinning/native-E2E/cross-platform/hardening invariants.
- `RELEASE_MANIFEST.json` records `loaderCompatibilityGA=true` plus the GA support-policy SHA-256. `release publish-check` fail-closes on certificate hash drift, runtime support hash drift, missing GA invariants or a non-GA certificate.
- Public loader capability output now reports the exact GA Minecraft versions, Java majors, install modes, legacy coverage and support-policy SHA-256 instead of the obsolete generic Java 17/21 constraint. Added mandatory 0.18.0 CI/preflight/repository-policy gates and GA drift regressions.

## 0.17.11 — Loader Compatibility RC

- Added `LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json`: a complete release certificate derived from the exact embedded compatibility targets, aggregate matrix and `COMPATIBILITY_CERTIFICATION.json`.
- The RC binds all 292 required targets with a deterministic SHA-256 evidence root, exact source commit/run, matrix/targets/certification hashes and a self-identifying `certificateId`.
- Added per-loader family coverage for Vanilla/Fabric/Quilt/Forge/NeoForge, six OS/architecture pairs, Java 8/16/17/21/25, client/integration scopes, immutable loader pins, loader-native E2E, cross-platform loader execution and loader hardening recovery.
- Release build fail-closes unless every RC invariant is true. The certificate is required by `RELEASE_MANIFEST.json`, its SHA-256 is recorded there, and the certificate itself is included in `SHA256SUMS`/Ed25519 signed release boundary.
- `release publish-check` recomputes the full certificate from embedded evidence; missing or tampered certificate/root/family/platform coverage is rejected. Added mandatory 0.17.11 CI/preflight/repository-policy gates and tamper regressions.

## 0.17.10 — Loader Hardening

- Added content-addressed SHA-256 loader payload cache for Fabric/Quilt Meta profiles and Forge/NeoForge installers. Immutable resolution locks can replay exact pinned bytes without mutable upstream availability; corrupt cache records/payloads are quarantined fail-closed.
- Forge/NeoForge pinned installer replay no longer depends on mutable `.sha1` sidecars. Verified installers are restored from the local SHA-256 cache, while first-time unpinned installs retain upstream checksum verification before cache commit.
- Added a durable processor recovery journal with `running`/`failed`/`completed` states, processor identity, attempts and installer binding. After interruption, verified completed outputs are adopted without rerun; incomplete or corrupt outputs are quarantined and the processor is executed again.
- Added cache-only recovery E2E for current Fabric/Quilt/Forge/NeoForge Linux x64 anchors. Aggregate/release certification requires upstream-independent recovery and, for Forge/NeoForge, installer + processor recovery; bundle verification recomputes the four hardening targets.
- Added mandatory 0.17.10 CI/preflight/repository-policy gates and raw `loader-hardening.json` / recovery package evidence.

## 0.17.9 — Cross-platform Loaders

- Added required cross-platform loader certification for Fabric 26.3, Quilt 26.3, Forge 26.3 and NeoForge 26.2 on Windows/Linux/macOS × x64/ARM64 (24 loader/platform targets; 292 total compatibility targets). Historical wide loader release grids remain Linux x64 regression baselines.
- Removed the Linux/x64-only client-certification guard from all four loader runners. Windows uses `.exe` runtime binaries, Linux uses Xvfb, and Windows/macOS launch the actual NeverRuntime client natively. CI now selects target Java architecture explicitly for x64/aarch64.
- NeverRuntime certification now reports the actual selected native directory. `verify-loader-platform.py` fail-closes unless materializer target evidence, native files and the runtime-selected directory all match the exact `natives/<os>/<arch>` tree (`macOS` maps to Mojang `osx`). It also records a deterministic `nativeTreeSha256`.
- Aggregate/release certification requires `loaderPlatformMaterialized`, `loaderNativesResolved` and `loaderPlatformLaunch` for all 24 targets, records `crossPlatformLoaderTargets`, and bundle verification recomputes the coverage. Added mandatory CI/preflight/repository gates and wrong-architecture/tamper regressions.

## 0.17.8 — Loader-native E2E

- Added a real dedicated-loader E2E boundary for the four 1.21.1 integration anchors: Fabric, Quilt, Forge and NeoForge now start a clean dedicated server using the exact immutable loader version resolved for the materialized client.
- Added `run-loader-native-e2e.sh`: it starts the exact loader server, requires healthy runtime state and exact loader artifacts, launches the actual materialized client through NeverRuntime with direct-connect, and requires the server log to prove `NeverLauncherCertification joined the game`.
- Added raw loader-native server/client/log/process/artifact/health evidence to compatibility artifacts. Aggregate validation now fail-closes on missing server health, loader-version match or actual join evidence.
- Release certification records the exact four `loaderNativeTargets`; bundle verification recomputes them from embedded matrix evidence and rejects tampered coverage.
- Added mandatory 0.17.8 offline, preflight and repository-policy gates plus regression tests for missing join/evidence and certification tampering. Existing Paper integration/revoke E2E and 0.17.7 immutable resolution pinning remain required.

## 0.17.7 — Loader Resolution & Pinning

- Added a production loader resolution lock for Fabric, Quilt, Forge and NeoForge. Mutable selectors resolve once to a concrete loader/artifact version; replay reads the lock before mutable upstream resolution and cannot silently move to a newer loader.
- Bound every lock to resolution provenance SHA-256, exact upstream Meta profile or installer SHA-256, final runtime profile SHA-256 и materialized-files SHA-256 and a deterministic reproducibility SHA-256. Lock/payload/profile tampering fails closed.
- Fabric/Quilt resolution provenance hashes the actual Meta response; Forge/NeoForge mutable resolution hashes the actual Maven `maven-metadata.xml`, while explicit immutable selectors use a deterministic explicit-resolution identity.
- Compatibility client and integration paths now materialize non-Vanilla loaders twice, require `resolutionPinned=true`, verify stable lock/reproducibility hashes, retain raw resolution locks, and expose machine-verifiable pin evidence in compatibility results.
- Release certification now records sorted `loaderPins`; bundle verification recomputes the pin set from embedded matrix evidence and rejects modified or missing pin coverage. Added mandatory 0.17.7 CI/preflight/repository gates and tamper regression tests.

## 0.17.6 — NeoForge Compatibility II

- Expanded NeoForge from the single 1.21.1 integration target to a mandatory 22-release production line from Minecraft 1.20.1 through current stable 26.2, with exact Java 17/21/25 binding and full integration retained for 1.21.1.
- Fixed real upstream version/artifact resolution: NeoForge 1.20.1 resolves the official `net.neoforged:forge` / `1.20.1-47.x` publication, while 1.20.2+ uses `net.neoforged:neoforge`; 26.x uses the full Minecraft-version scheme such as `26.2.0.x`. Explicit incompatible loader versions fail closed.
- Added NeoForge actual-client certification: verified official installer, client processors and outputs, generated profile/libraries, package verification, immutable loader evidence, then real profile launch through NeverRuntime on the exact target Java.
- Added `neoforge-install.json` / `neoforge-certification.json` CI evidence, separate `neoForgeVersions` release coverage with tamper verification, mandatory 0.17.6 matrix/preflight/repository gates and regression tests.
- Promoted the public NeoForge loader catalog entry from `planned` to the production Compatibility Engine materializer; Fabric/Quilt/Forge gates remain mandatory regression boundaries.

## 0.17.5 — Forge Legacy 1.7.10

- Added a real Forge 1.7.10 V1 universal-installer path with LaunchWrapper and the era-correct `cpw.mods.fml.common.launcher.FMLTweaker`; Java 8 is enforced and 1.7.10 never falls through to the modern processor pipeline.
- Legacy `versionInfo` without `inheritsFrom` is normalized to Vanilla 1.7.10 while preserving old metadata, and legacy Forge Maven URLs are upgraded narrowly from the retired `files.minecraftforge.net/maven` HTTP base to the official HTTPS Maven host.
- NeverRuntime can resolve pre-`downloads.classifiers` native metadata by deriving native classifier paths from Maven coordinates, while remaining fail-closed for incomplete modern classifier maps.
- Added explicit install evidence (`legacyTweaker`, `legacyBaseVersion`, `legacyProfileNormalized`), actual-client certification through NeverRuntime, the required Forge 1.7.10/Java 8 target, 0.17.5 matrix/release/repository gates, and regression tests.
- Retained independent Forge Legacy 1.12.2 and 43-release Forge Modern 1.13.2+ certification gates.

## 0.17.4 — Forge Legacy 1.12.2

- Added a real Forge 1.12.2 legacy installer path for classic V1 `install_profile.json` archives: NeverLauncher parses `install` + nested `versionInfo`, extracts the embedded universal JAR from `install.filePath`, verifies SHA-1, writes the Maven artifact and preserves the original runtime profile instead of pretending the installer has modern processors.
- Added a separate path for repacked Forge 1.12.2 installers that contain `version.json` but intentionally have empty `data/processors`; their embedded Maven universal artifact is materialized and verified without processor emulation.
- Legacy library handling now honors old `clientreq` and `checksums` fields in both the Go materializer and NeverRuntime, preventing server-only libraries from entering the client tree/classpath while retaining strict checksum validation.
- Forge legacy certification requires LaunchWrapper + `FMLTweaker`, exact Java 8, package verification, immutable resolved Forge version, universal SHA-1/SHA-256 evidence and actual client launch through NeverRuntime.
- Added the required Forge 1.12.2 target, 0.17.4 matrix/release/repository gates, real legacy-installer regression fixtures, and retained the separate 43-release processor-based Forge Modern 0.17.3 gate.

## 0.17.3 — Forge Modern

- Promoted processor-based Forge to a mandatory executable compatibility line covering **43 official Forge release points from Minecraft 1.13.2 through 26.3**, with exact Java 8/16/17/21/25 binding. Forge 1.13/1.13.1 are not advertised because the modern processor installer line starts at 1.13.2.
- Hardened the production Forge installer executor: client processors are mandatory, Installer spec v1 inline `{TOKEN}` substitution is supported, `{MINECRAFT_VERSION}`/`{INSTALLER}`/`{LIBRARY_DIR}`/`{SIDE}` and installer data/artifact tokens resolve fail-closed, and referenced packaged data is extracted explicitly instead of treating the installer as metadata only.
- Forge client certification now runs `forge-package` with the exact target Java, verifies the materialized package, checks concrete immutable Forge resolution plus installer/profile SHA-256 and processor execution evidence, then launches the materialized Forge profile through NeverRuntime.
- `1.21.1` retains full integration E2E; the other Forge Modern targets use Linux x86_64 actual-client certification. Release aggregation rejects missing/duplicate releases, wrong Java/scope/platform, mutable resolved Forge versions and incomplete processor/client evidence.
- Added raw `forge-install.json`/`forge-certification.json` CI artifacts, mandatory 0.17.3 offline/repository/preflight gates, and regression tests for the 43-release grid, processor tokens and release certification.

## 0.17.2 — Quilt Compatibility II

- Expanded executable Quilt compatibility from the single 1.21.1 integration target to **48 stable Minecraft releases from 1.14 through 26.3**, bound to exact Java 8/16/17/21/25.
- Quilt client certification now executes the production `quilt-package` materializer against official Quilt Meta v3, verifies the materialized package and Maven libraries, resolves a concrete immutable Quilt Loader, and launches the real materialized Quilt `KnotClient` profile through NeverRuntime.
- Hardened Quilt `latest-stable` resolution for Meta responses that omit Fabric-style stability metadata: semantic-version prereleases are rejected, no-stable responses fail closed, and exact prerelease selectors remain explicitly usable.
- Added fail-closed release certification for the complete Quilt grid, exact Java/scope/platform mapping, immutable Loader evidence, actual-client launch evidence, and retained full integration E2E for Quilt 1.21.1.
- Added dedicated Quilt install/certification artifacts, offline release gate, repository policy enforcement, CI/preflight wiring, and regression tests for missing/duplicate releases, wrong Java and mutable Loader results.
- Updated the public loader catalog so Fabric and Quilt expose their production Compatibility Engine materializers instead of obsolete `planned` adapters.

## 0.17.1 — Fabric Compatibility II

- Expanded the executable Fabric compatibility line from the single 1.21.1 integration target to **48 stable Minecraft releases from 1.14 through 26.3**, with exact Java 8/16/17/21/25 binding.
- Fabric client-scope certification now runs the production materializer against official Fabric Meta, downloads and checksum-verifies the real Fabric profile/libraries, builds and verifies the local NeverLauncher client package, and resolves `latest-stable` to a concrete immutable Loader version.
- Added actual Fabric client launch certification through NeverRuntime using the materialized Fabric profile/main class on the exact target Java. A metadata-only or package-only result cannot satisfy the target.
- Compatibility aggregation and release certification fail closed on a missing/duplicate Fabric release, wrong Java/scope/platform, incomplete Fabric evidence, mutable resolved Loader version, failed real-client launch, or missing JRE/platform attestation.
- `1.21.1` keeps the full integration E2E path; the remaining Fabric releases use actual-client certification on Linux x86_64. Existing Vanilla GA, loader-family, cross-platform, matching-server and hardening requirements remain mandatory.
- Added regression tests for the complete Fabric release grid, exact Java mapping and immutable Loader evidence.

## 0.17.0v3 — Java 21/25 Vanilla release-gap completion

- Added mandatory actual-client targets `1.21.11` on exact Java 21 and `26.2` on exact Java 25 without changing the product semantic version (`VERSION` remains `0.17.0`).
- Vanilla client materialization and matching-server installation now fail closed for both v3 releases when Mojang `javaVersion.majorVersion` is missing or conflicts, before client/server JAR download.
- NeverRuntime independently enforces the same exact Java-major mapping from materialized metadata, preventing local metadata tampering from selecting another runtime.
- Compatibility aggregation and release certification require both v3 targets on Linux x86_64 client scope; the GA floor is now 109 required Vanilla targets covering 104 unique release IDs.
- Added executable regression coverage for valid v3 client materialization, server-side pre-download Java rejection, missing targets, wrong Java majors, runtime enforcement and mandatory repository/release gates.

## 0.17.0v2 — Complete Java 16/17 Vanilla grid

- Added the nine requested Java-transition Vanilla releases as mandatory actual-client targets: `1.17` on exact Java 16; `1.18`, `1.18.1`, `1.19`, `1.19.1`, `1.19.2`, `1.19.3`, `1.20`, `1.20.3` on exact Java 17.
- Vanilla materializer and matching-server installer now fail closed for the exact v2 grid when Mojang `javaVersion.majorVersion` is missing or conflicts, before client/server artifacts are downloaded.
- NeverRuntime independently enforces the same v2 Java-major policy from materialized metadata, so a local metadata edit cannot downgrade/upgrade the runtime.
- Compatibility matrix/release certification now require all nine v2 targets on Linux x86_64 client scope; the GA floor is 107 required Vanilla targets covering 102 unique release IDs.
- Added regression gates for missing v2 releases, wrong Java majors, exact release-set integrity and real modern metadata materialization. Product semantic version remains `0.17.0`; `v2` is the compatibility maintenance revision.

## 0.17.0v1 — Complete Legacy Vanilla grid

- Expanded the production Vanilla compatibility base with 53 exact Legacy Vanilla releases requested for `1.2.1`–`1.16.4`; the certified GA matrix now contains 98 required Vanilla targets covering 93 unique release IDs.
- Vanilla materialization now fail-closed enforces Java 8 for official 1.x releases through `1.16.5`, including metadata that omits `javaVersion`, and rejects a conflicting declared Java major instead of silently selecting it.
- Materialization rejects version metadata that contains neither executable modern `arguments.game` nor legacy `minecraftArguments`, preventing a nominally installed but non-launchable client.
- NeverRuntime independently applies the same Legacy Java 8 rule and executable-argument validation before launch, so bypassing the installer cannot weaken the runtime policy.
- Compatibility aggregation, release certification, offline GA gate and repository policy require the complete 53-release v1 grid; removing a listed release or changing its Java/scope/platform attributes fails certification.
- Added regression coverage for the exact 53-release set, Java-major tampering, missing launch arguments and missing release targets. Product semantic version remains `0.17.0`; `v1` denotes this compatibility maintenance revision.

## 0.17.0 — Minecraft Compatibility II GA

- Compatibility II promoted to GA with 45 required Vanilla targets covering 40 unique release IDs and exact Java 8/16/17/21/25 requirements; existing loader-family, cross-platform, matching-server and hardening gates remain mandatory.
- Every compatibility target now runs a reusable JRE certifier before Minecraft launch. It resolves the real `java`/`java.exe`, hashes the executable with SHA-256 and records vendor, runtime version, VM name, `java.home`, OS, architecture and exact detected major.
- `compatibility-result.json` binds `jreVendor`, `jreRuntimeVersion` and `jreExecutableSha256` to `jreCertified=true`; aggregator rejects missing, malformed or OS/arch-mismatched JRE evidence.
- Public `matrix.json` derives `jreBase` from actual passing target evidence instead of a hand-authored JRE table.
- `COMPATIBILITY_CERTIFICATION.json` now carries concrete certified JRE builds and target counts; release verification recomputes and compares the JRE build set.
- Production Release Candidate, Production Delivery Release and release manifest checks require `minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base` for 0.17.0+.
- Added JRE attestation regression tests and mandatory 0.17.0 repository/preflight/CI gate.

## 0.16.11 — Compatibility Hardening

- Vanilla artifact downloads recover interrupted `.nlpart` files with validated HTTP Range/`Content-Range`; every resumed result is still bounded by expected size and must pass the final Mojang SHA-1 before atomic publication.
- Corrupt compatibility cache entries are moved to a bounded quarantine instead of being silently overwritten; already-complete verified partials are atomically promoted without another network request.
- Exact-version Mojang `version.json` metadata is cached with SHA-1/SHA-256/size and identity binding, allowing verified outage recovery only for exact versions. Mutable `latest`/snapshot selectors and versions absent from a successfully fetched authoritative manifest stay fail-closed.
- Pinned asset-index and Mojang server/client artifacts can reuse checksum-verified local cache during upstream failure; malformed asset hashes and unsafe remote URLs are rejected before path/network use.
- Native ZIP extraction rejects traversal, symlinks and unsupported entries, enforces entry/count/total-uncompressed limits, and publishes `natives/<os>/<arch>` transactionally; legacy virtual assets/resources are also built in staging so a failed refresh preserves the previous verified tree.
- Compatibility HTTP retry handling preserves request headers and honours bounded `Retry-After`; URL validation rejects credentials, fragments, control characters and private literal upstreams unless explicitly opted in.
- Managed Java cache schema 1.2 binds cached runtimes to OS/arch, vendor archive SHA-256 and the SHA-256 of the actual Java executable before `java -version`; legacy/incomplete cache records are reinstalled instead of trusted.
- Managed Java upstream requests use bounded transient retries with HTTPS downgrade protection. Corrupt archives are quarantined, symlink partials are rejected, and a complete verified partial archive can recover atomically after interruption.
- Release compatibility certification for 0.16.11 appends `compatibility-hardening-cache-recovery-upstream-failure-security`; existing 49-target / 45-Vanilla, cross-platform and Actual Client E2E II gates remain mandatory.

## 0.16.10 — Actual Client E2E II / real clients + matching servers

`0.16.10` усиливает actual-client certification: representative Vanilla versions больше не считаются совместимыми только по успешному запуску клиента — CI поднимает официальный Mojang server той же версии и требует фактический вход клиента.

- Добавлен production `nl runtime vanilla-server`: server artifact берётся из `downloads.server` verified Mojang `version.json`, проверяется по declared size/SHA-1, атомарно кэшируется и получает локальный SHA-256 evidence.
- Обязательные matching pairs: `1.7.10`/Java 8, `1.17.1`/Java 16, `1.20.4`/Java 17, `1.21.10`/Java 21 и `26.3`/Java 25. Client и server обязаны иметь одну exact Minecraft version и запускаться на target Java major.
- NeverRuntime `certify-vanilla` поддерживает прямое подключение через `--server`/`--server-port`; matching E2E запускает реальный клиент и считает PASS только после server-log evidence о входе `NeverLauncherCertification`.
- `matching-server.json`, `vanilla-server-install.json` и server log входят в machine-verifiable evidence; `serverVersionMatched`, `serverHealthy` и `clientJoinedServer` обязательны.
- Compatibility aggregator и CLI release certification fail-closed требуют policy `actual-client-e2e-II-real-clients-matching-mojang-servers`; подмена matching target обычным client-launch result отклоняется.
- Остальная 49-target matrix, cross-platform 26.3 и loader integration E2E сохраняются без ослабления.

## 0.16.9 — Cross-platform Vanilla / Windows, Linux, macOS × x64, ARM64

`0.16.9` делает Vanilla certification нативной для всех шести desktop OS/architecture targets вместо Linux/x64-only запуска.

- Minecraft 26.3 сертифицируется отдельным actual-client target на Linux x64/ARM64, Windows x64/ARM64 и macOS x64/ARM64; каждый CI result обязан совпадать с фактически обнаруженным host OS/arch.
- Vanilla materializer разделяет extracted natives по `natives/<os>/<arch>` и фильтрует architecture-specific Mojang/LWJGL native classifiers; x64 и ARM64 больше не используют общий native cache одной ОС.
- NeverRuntime выбирает тот же OS+arch native directory и независимо от materializer фильтрует composite Mojang OS rules/native classifiers перед построением classpath.
- Compatibility workflow планирует native GitHub-hosted runners и exact Java для каждого target; Linux client certification использует Xvfb, Windows/macOS запускают реальный клиент на native desktop session.
- Release certification fail-closed требует policy `cross-platform-vanilla-windows-linux-macos-x64-arm64`, все шесть 26.3 targets и `platformMatched=true` evidence.

## 0.16.8 — Java 25 Vanilla / 26.1.x + 26.3

`0.16.8` добавляет рабочую Java 25 Vanilla certification для новой календарной линии Minecraft Java Edition.

- Exact Java 25 policy применяется к `26.1`, `26.1.1`, `26.1.2` и `26.3`; missing/mismatched `javaVersion.majorVersion` отклоняется до загрузки client artifacts.
- NeverRuntime независимо валидирует тот же exact major, поэтому локально подменённая metadata не может уйти на Java 21 или другой runtime.
- Compatibility matrix содержит отдельные actual-client targets для всех четырёх выпущенных версий; каждый target использует verified Mojang materialization, package integrity, runtime resolution и реальный client launch.
- Release certification 0.16.8 fail-closed требует policy `vanilla-26.1.x-26.3-java25-exact`, Java 25 coverage и полный evidence для каждого target.
- Managed Java II уже поставляет Java 25 on-demand; Java 21/16/17 и Java 8 legacy gates сохраняются без ослабления.

## 0.16.7 — Java 21 Vanilla / 1.20.5–1.21.10

`0.16.7` превращает Java 21 Vanilla coverage из двух Baseline II anchors в обязательную actual-client release-line certification для 1.20.5/1.20.6 и всей 1.21.x линии до 1.21.10.

- Обязательные targets: `1.20.5`, `1.20.6`, `1.21`, `1.21.1`, `1.21.2`, `1.21.3`, `1.21.4`, `1.21.5`, `1.21.6`, `1.21.7`, `1.21.8`, `1.21.9`, `1.21.10` на exact Java 21.
- Vanilla materializer проверяет официальный `javaVersion.majorVersion` до скачивания client/assets; Java 17, missing metadata и любой другой major для этого диапазона отклоняются fail-closed.
- NeverRuntime независимо применяет ту же exact-Java 21 policy к materialized Mojang metadata, поэтому локальная подмена metadata не обходит gate.
- `1.21.1` сохраняет integration E2E с Paper/session revoke; остальные release-line targets выполняют verified materialization, runtime resolution и реальный Minecraft client launch под Xvfb.
- Release certification требует policy `vanilla-1.20.5-1.21.10-java21-exact` и не проходит при удалении любой обязательной версии или Java mismatch.
- Managed Java II 8/16/17/21/25, Java 8 legacy, Java 16/17 Vanilla и Baseline II сохраняются.

## 0.16.6 — Java 16/17 Vanilla / 1.17.1–1.20.4

`0.16.6` переводит переходный диапазон Vanilla 1.17.1–1.20.4 из трёх representative anchors в обязательную actual-client release-line certification и делает Java transition исполняемой runtime policy.

- Обязательная линия: `1.17.1` на exact Java 16; `1.18.2`, `1.19.4`, `1.20.1`, `1.20.2`, `1.20.4` на exact Java 17. Каждый target выполняет verified Mojang materialization, package integrity, Compatibility Engine resolution и фактический запуск клиента под Xvfb.
- Vanilla materializer fail-closed проверяет официальный `javaVersion.majorVersion` до скачивания client/assets: 1.17.1 обязан объявлять Java 16, а release 1.18.x–1.20.4 — Java 17. Отсутствующее или противоречащее metadata поле больше не может тихо уйти в legacy Java 8 fallback.
- NeverRuntime применяет ту же independent exact-Java policy при runtime resolution, поэтому локально подменённая metadata также отклоняется до запуска JVM.
- Compatibility matrix/release certification 0.16.6 нельзя сузить до старых anchors: обязательны 1.19.4/1.20.1/1.20.2, exact target Java, actual-client evidence и policy `vanilla-1.17.1-1.20.4-java16-17-exact`.
- Managed Java II 8/16/17/21/25, Legacy Vanilla Java 8 и Baseline II сохраняются без ослабления.

## 0.16.5 — Managed Java II / Java 8, 16, 17, 21, 25

`0.16.5` переводит Managed Java из частично реализованного набора major-веток в исполняемый production lifecycle для Java 8/16/17/21/25 без подмены отсутствующих vendor binaries декларациями.

- NeverRuntime принимает только сертифицированные majors `8/16/17/21/25`; Java 16 добавлена в реальный resolver, CLI и cache/install path.
- Adoptium resolution сначала использует current `assets/latest`, затем исторический GA `assets/feature_releases/<major>/ga`; это позволяет устанавливать EOL Java 16, которая больше не присутствует в current releases UI. Предпочитается JRE, а JDK допускается только как vendor GA fallback, если JRE для конкретной major/platform отсутствует.
- Любой on-demand runtime проходит HTTPS-only download, declared size bound, exact vendor SHA-256, безопасную распаковку, symlink/path containment, фактический `java -version` exact-major check, atomic install и повторную cache verification.
- Bundled Temurin 21 six-platform distribution 0.15.5 сохраняется как bootstrap; Java 8/16/17/25 не притворяются универсальными six-target artifacts и разрешаются по фактической Adoptium platform availability.
- CI собирает настоящий NeverRuntime и выполняет install → `java -version` → cache reuse для Java 8/16/17/21/25; результат фиксируется в `MANAGED_JAVA_II_EVIDENCE.json`, входит в release bundle и обязателен для 0.16.5 release/RC/Production Delivery certification.

## 0.16.4 — Legacy Vanilla 1.0.0–1.7.10 / Java 8

`0.16.4` расширяет исполняемый legacy-контур до первых release-линий Vanilla и закрывает несовместимости pre-1.6 metadata/assets, которые не покрывал gate 0.16.3.

- Обязательная pre-1.7 линия: `1.0` (CLI alias `1.0.0`), `1.1`, `1.2.5`, `1.3.2`, `1.4.7`, `1.5.2`, `1.6.4`, `1.7.10`; каждый target использует exact Java 8, verified Mojang materialization и `NeverRuntime certify-vanilla`.
- Vanilla materializer принудительно строит legacy virtual asset tree для индексов `pre-1.6`/`legacy` в `assets/virtual/<asset-index>`, очищает stale generated files перед повторной materialization и продолжает проверять SHA-1/size каждого upstream asset.
- NeverRuntime формирует pre-1.6 `${auth_session}` в legacy session-id формате и поддерживает `${game_assets}`, направляет `${game_assets}` в фактический virtual asset tree и применяет Java 8 fallback ко всему release-диапазону 1.0–1.16.5 при отсутствии `javaVersion`.
- `1.0.0` принимается CLI как пользовательский alias и нормализуется к metadata id `1.0`; package/evidence сохраняют фактический resolved Minecraft version.
- Release certification 0.16.4 fail-closed требует всю pre-1.7 Java 8 линию; gate 0.16.3 для 1.7.10–1.16.5, Baseline II и Fabric/Quilt/Forge/NeoForge integration coverage сохраняются.

## 0.16.3 — Legacy Vanilla 1.7.10–1.16.5 / Java 8

`0.16.3` превращает legacy Vanilla coverage из трёх representative anchors в исполняемый Java 8 release-line gate и исправляет два runtime-дефекта, обнаруженных на настоящем metadata старых клиентов.

- Обязательная legacy-линия: `1.7.10`, `1.8.9`, `1.9.4`, `1.10.2`, `1.11.2`, `1.12.2`, `1.13.2`, `1.14.4`, `1.15.2`, `1.16.5`; каждый target использует exact Java 8, verified Mojang materialization и `NeverRuntime certify-vanilla`.
- Vanilla materializer больше не синтезирует несуществующий classpath JAR для classifier-only библиотек (`lwjgl-platform`, `jinput-platform` и аналогов): скачиваются и распаковываются только реальные native classifiers из Mojang metadata.
- NeverRuntime применяет ту же classifier-only семантику при построении classpath, поддерживает `${user_properties}`/`${profile_properties}` для legacy `minecraftArguments` и возвращает Java 8 как resolved runtime для release-диапазона 1.7.10–1.16.5, если `javaVersion` отсутствует.
- Strict upstream mode остаётся fail-closed: обычная библиотека без проверяемого Mojang artifact отклоняется; Maven-coordinate fallback сохраняется только для явно non-strict/local metadata.
- Release certification 0.16.3 не может пройти при удалении любой legacy release-line цели или при Java mismatch; Baseline II 1.17.1–1.21.1 и Fabric/Quilt/Forge/NeoForge integration coverage сохраняются.

## 0.16.2 — Vanilla Compatibility Baseline II

`0.16.2` заменяет одноверсионную Vanilla certification на исполняемую многоверсионную модель без новой DB migration и без ослабления существующего integration E2E.

- Обязательная Vanilla-линия теперь включает 1.7.10/1.12.2/1.16.5 на Java 8, 1.17.1 на Java 16, 1.18.2/1.20.4 на Java 17 и 1.20.6/1.21.1 на Java 21. Release gate требует весь набор и Java coverage 8/16/17/21.
- Добавлен `NeverRuntime certify-vanilla`: он разрешает реальную Mojang metadata/classpath, проверяет exact Java major и запускает фактический материализованный Minecraft client под certification timeout с машинным result/log evidence.
- Compatibility Engine корректно запускает legacy Vanilla metadata без `arguments.jvm`, добавляя launcher JVM baseline и сохраняя единый resolver для старых и новых версий.
- Compatibility CI разделяет `client` и `integration` scope: исторические Vanilla версии получают реальный client-launch gate, а 1.21.1 + Fabric/Quilt/Forge/NeoForge сохраняют полный signed release, clean sync, actual client, Paper join, session revoke и health evidence.
- Python matrix aggregator и Go release certification связывают target/result по Minecraft, loader, OS/arch, Java major и scope; 0.16.2 fail-closed отклоняет отсутствующий baseline anchor, Java mismatch, неполный evidence и попытку сузить обязательное покрытие.
- Публичный runtime matrix и compatibility documentation обновлены до 12 обязательных targets.

## 0.16.1 — CI Recovery

`0.16.1` восстанавливает обязательный CI-контур поверх Production Delivery Release 0.16.0 без новой DB migration и без отключения functional/security gates.

- Исправлен Gradle repository policy: Fabric Loom 1.17.21 может добавить `LoomLocalRemappedMods`, поэтому ServerBridge и actual-client compatibility больше не падают до сборки plugins.
- Production Compose validation получает обязательные `NEVERLAUNCHER_WEBAUTHN_RP_ID` и `NEVERLAUNCHER_WEBAUTHN_ORIGINS`.
- Desktop frontend readiness/binding models приведены к фактической структуре Backend API; устранены TypeScript `TS2353` в production build.
- NeverRuntime исправляет `E0716` в OS target normalization; Linux-only unused imports устранены для strict `clippy -D warnings`.
- Tauri Device Trust включает `hardware-enclave` feature `encryption`, необходимую для Linux TPM/software encryptor implementation.
- Windows production hardening smoke gate синхронизирован с реальным `signtool sign/verify` + RFC3161 + Authenticode pipeline и текущим package verification boundary.
- Rust CI нормализует formatting перед test/clippy/build, не маскируя compile/test/security failures.

## 0.16.0 — Production Delivery Release

`0.16.0` — GA-релиз production delivery-контура 0.15.1–0.15.11. Он не добавляет DB migration и не ослабляет RC: `PRODUCTION_RELEASE_CANDIDATE.json` остаётся exact-commit pre-sign certification, а новый `PRODUCTION_DELIVERY_RELEASE.json` промотит его в stable six-target release и сам входит в Release Verification v2 signature boundary.

- Добавлен `PRODUCTION_DELIVERY_RELEASE.json` schema 1.0 со статусом `production-delivery-release`, `channel=stable`, exact `sourceCommit`, six canonical targets, hash кандидата/cohort, immutable `publicBaseUrl`, sorted anchor set и агрегированный `boundarySha256`.
- GA certificate привязывает RC, `DELIVERY_MANIFEST.json`, `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json`, Windows/Linux/macOS production evidence, Managed JRE manifest/evidence, root-signed trust policy, Compatibility/Device Trust/Guard/ServerBridge certifications, SBOM и provenance.
- Production Delivery Release допускает только GA SemVer без prerelease/build suffix и HTTPS public origin с exact version segment (`0.16.0`/`v0.16.0`), чтобы stable release не мог ссылаться на mutable `/latest` origin.
- `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json` для 0.15.11+ теперь публикует `PRODUCTION_RELEASE_CANDIDATE.json` как отдельный control (раньше candidate создавался после Delivery Manifest и public E2E не мог его скачать); для 0.16.0 matrix дополнительно публикует GA certificate. Post-publish `delivery public-e2e` получает оба certification слоя и затем выполняет полный `release verify` по публичным bytes.
- `RELEASE_MANIFEST.json` фиксирует `channel=stable`, `releaseStatus=production-delivery-release` и `productionDeliveryReleaseSha256`; verifier сверяет эти поля с GA certificate и exact source commit.
- Добавлена `nl release production-verify <bundle>`; `release verify`, `publish-check`, `build-release.sh`, release-bundle gate, preflight/CI, release doctor и repository policy требуют GA certification для 0.16.0+.
- Security release policy для 0.16.0 требует Delivery Manifest, Public Matrix, RC certificate и Production Delivery Release certificate как отдельные fail-closed controls.

Перед публикацией выполняются `release candidate-verify`, `release production-verify`, `release sign`, `release verify` и `release publish-check`; после публикации GitHub workflow выполняет public E2E по фактически опубликованным bytes.

## 0.15.11 — Production release candidate

`0.15.11` переводит накопленный Production Delivery 0.15.x в единый machine-verifiable release-candidate boundary. RC больше не допускает частично сертифицированный bundle: Compatibility, Device Trust и Guard CI evidence обязаны относиться к одному exact source commit, production Windows/macOS artifacts должны быть реально vendor-signed/notarized, а весь pre-sign cohort фиксируется отдельным сертификатом и затем входит в Ed25519 release signature. DB migration не требуется.

- Добавлен `PRODUCTION_RELEASE_CANDIDATE.json` schema 1.0 со статусом `production-release-candidate`, exact `sourceCommit`, фиксированным набором обязательных gates, полным sorted inventory pre-sign release cohort и агрегированным `cohortSha256`.
- `release build` для 0.15.11+ требует полный Compatibility + Device Trust + Guard CI certification set; все три certification должны иметь один commit, совпадающий с SLSA `PROVENANCE.json` `sourceCommit`.
- Windows evidence при RC build проверяется только в production Authenticode/RFC3161 режиме, macOS — только Developer ID + Accepted notarization/stapling/Gatekeeper; unsigned/ad-hoc candidate больше не может стать 0.15.11 release bundle.
- `scripts/release/build-release.sh` для RC требует Git checkout, exact `NEVERLAUNCHER_SOURCE_COMMIT == HEAD` и отсутствие tracked/staged изменений относительно HEAD до начала сборки.
- Candidate cohort фиксирует все top-level release bytes до создания `RELEASE_MANIFEST.json`/`SHA256SUMS`; добавление, удаление или изменение любого cohort file после certification ломает `release candidate-verify`. Post-sign `SHA256SUMS.sig`/`PROVENANCE.json.sig` исключены из pre-sign cohort и проверяются собственными cryptographic gates.
- Добавлена `nl release candidate-verify <bundle>`; `release verify`/`publish-check` для 0.15.11+ повторно проверяют RC certification и production-only delivery evidence. Сам `PRODUCTION_RELEASE_CANDIDATE.json` включён в `RELEASE_MANIFEST.json`, `SHA256SUMS` и Release Verification v2 signature boundary.
- Добавлены unit/regression gate `production-release-candidate-01511.py`, release doctor/repository policy/preflight/CI integration и обязательное наличие RC certification в release-bundle gate.

Перед публикацией выполняйте `nl release candidate-verify` и затем `nl release publish-check` с внешним root public key/current trust policy/persistent trust state. Production release script выполняет оба шага автоматически.

## 0.15.10 — Migration + stabilization

`0.15.10` стабилизирует production delivery после six-target E2E и выполняет миграцию локального updater/trust state без новой DB migration. Upgrade 0.15.9 → 0.15.10 сохраняет release trust root, текущий trust epoch, Desktop/Guard/Runtime installation и durable updater journals; старые локальные форматы переводятся автоматически/fail-closed.

- Release trust state мигрирует с schema `2.0` на `2.1`: сохраняются monotonic trust epoch/release version, добавляются `highestReleaseManifestSha256` и `stateRevision`. После первого принятия конкретной версии другой `RELEASE_MANIFEST.json` с той же версией отклоняется как same-version equivocation.
- `nl release verify/publish-check` для 0.15.10+ удерживает внешний `<trust-state>.lock` на весь verify→commit boundary. Параллельный verifier не может пройти anti-rollback precheck со старым snapshot state; stale lock от завершившегося PID восстанавливается автоматически, live PID блокирует второй процесс.
- Legacy macOS state из `.neverlauncher/updater/component-update-state.json` переносится в общий `.neverlauncher/component-update-state.json`; при наличии двух state выбирается более новая версия, а одинаковая версия с различными component hashes останавливает migration fail-closed.
- `nl update migrate-state --root <install>` выполняет crash recovery, component-state migration и terminal-payload cleanup. `update recover` теперь делает ту же стабилизацию автоматически.
- После durable `rolled-back`/`committed` journal staging/backup/failed payload очищаются, но audit journal сохраняется. Cleanup никогда не удаляет component-tree path вне `.neverlauncher/updater`.
- Исправлен repository-policy runner: итоговый FAILED/OK вычисляется после всех policy blocks, поэтому поздние проверки больше не могут silently добавлять ошибки после уже напечатанного `OK`.
- Добавлены regression/self-test gate `migration-stabilization-01510.py`, unit tests trust-state migration/lock/component-state migration/rollback cleanup и обязательная интеграция в CI, preflight, release doctor и publish-check.

DB migration не требуется. Перед rollout достаточно сохранить backup локального install/trust state; первый 0.15.10 verify/update мигрирует его атомарно. Для явной проверки используйте `nl update migrate-state --root <install>` и `nl update stabilization-self-test`.

## 0.15.9 — Public Production Delivery Matrix + E2E

`0.15.9` делает production delivery публично проверяемым после публикации: release bundle содержит точную six-target матрицу Windows/Linux/macOS × x64/ARM64 с реальными URL, SHA-256/size и привязкой к Managed JRE, а post-publish E2E скачивает опубликованные bytes и повторяет Release Verification v2. DB migration не требуется.

- Добавлен `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json`: полный inventory фактического `DELIVERY_MANIFEST.json`, HTTPS URL каждого artifact и канонические target-записи CLI/Desktop/Guard/Runtime/package/Managed JRE; Linux дополнительно требует API.
- Матрица fail-closed требует ровно шесть production target и exact canonical artifacts из Windows/Linux/macOS production packaging; отсутствующий Runtime/package/JRE или рассинхрон SHA-256/size/URL отклоняются.
- Добавлены `nl delivery public-matrix`, `verify-public-matrix` и `public-e2e`; E2E потоково скачивает публичные assets, проверяет Content-Length/SHA-256, ограничивает redirects доверенными release-hosts и затем запускает полный `verifyReleaseBundleWithTrust`.
- Public matrix входит в `RELEASE_MANIFEST.json`, `SHA256SUMS` и Release Verification v2 signature boundary, но не включается внутрь `DELIVERY_MANIFEST.json`, исключая circular hash dependency.
- Добавлен post-publish `.github/workflows/public-production-delivery.yml`, который на событии GitHub Release `published` скачивает публичный релиз, использует внешний offline-root/current trust policy и сохраняет `PUBLIC_DELIVERY_E2E_REPORT.json`.
- Исправлен Windows aggregate delivery: `neverruntime-windows-{x64,arm64}.exe`, уже собираемый/подписываемый с 0.15.7, теперь обязателен в production staging и загружается Windows delivery workflow.

## 0.15.8 — Release Verification v2 + trust/key lifecycle

`0.15.8` заменяет single-key release verification на root-anchored trust hierarchy. Offline root подписывает versioned trust policy, а online release keys ротируются/отзываются независимо. Проверка релиза сохраняет monotonic trust state и fail-closed блокирует rollback trust epoch и release version. DB migration не требуется.

- Добавлен `RELEASE_TRUST_POLICY.json` schema 2.0: trust domain, monotonic epoch, active/verify-only/revoked Ed25519 release keys, activation/retirement metadata и offline-root signature.
- `security rotate-key` и `security revocation-list` двигают trust epoch; `security trust-policy` экспортирует root-signed policy из key registry, а `security trust-verify` проверяет её внешним root public key.
- `SHA256SUMS.sig` для 0.15.8+ стал Release Verification v2 envelope и криптографически связывает SHA256SUMS, RELEASE_MANIFEST hash/version, trust epoch, key id/fingerprint и signedAt.
- `release verify/publish-check` требуют внешний root trust anchor и persistent trust state; downgrade policy epoch/release version, revoked key, signature после retirement, expired/tampered policy и root/key reuse блокируются fail-closed.
- `PROVENANCE.json.sig` проверяется тем же trusted release key; root/private/release private keys никогда не принимаются из release bundle.
- В verification добавлена strict bundle path validation для required files, artifacts и SHA256SUMS, чтобы абсолютные/`..` paths не читались за пределами release directory.
- `scripts/release/build-release.sh`, release bundle gate, CI, strict preflight, release doctor и repository policy переведены на v2 trust inputs/state.

## 0.15.7 — Desktop/Guard/Runtime transactional update

`0.15.7` переводит self-update пользовательской поставки на Unified Transactional Updater Core: Desktop, NeverGuard и NeverRuntime обновляются как один проверенный transaction boundary. На Windows/Linux применяется adjacent-file transaction, а на macOS целиком переключается подписанный/notarized `.app`, чтобы не разрушать подпись bundle. DB migration не требуется.

- Добавлен production `component_update.go`: pinned package SHA-256, safe ZIP/tar extraction, platform/architecture validation, verified staging, durable journals, crash recovery и automatic rollback.
- Desktop Tauri передаёт обновление внешнему `neverlauncher-cli update components` helper, останавливает NeverGuard, передаёт PID текущего Desktop и завершает процесс; helper ждёт освобождения executable, выполняет commit и перезапускает Desktop только после успешной проверки.
- Windows x64/ARM64 package теперь включает подписанные `neverlauncher-desktop.exe`, `neverguard.exe`, `neverruntime.exe` и CLI helper; component manifest хранит Authenticode signer/timestamp binding.
- Linux x64/ARM64 и macOS x64/ARM64 package получают `COMPONENT_UPDATE_MANIFEST.json`, связанный с фактическими hashes/sizes package manifest; macOS manifest включается до outer bundle signing/notarization.
- NeverRuntime Guard package verification принимает новые canonical Windows/Linux/macOS production manifests, сохраняя backward compatibility с legacy Guard CI packages.
- Добавлены `nl update components` и `nl update component-self-test`; publish-check, repository policy, strict preflight и native CI делают 0.15.7 update boundary обязательным.

## 0.15.6 — Unified Transactional Updater Core

`0.15.6` переводит локальное применение обновлений на единый crash-recoverable transaction engine для Windows/Linux/macOS. Client install/update/package-apply теперь сначала полностью stage+verify новые bytes, фиксируют durable journal и backup touched-файлов, и только затем переключают live tree. DB migration не требуется.

- Добавлен production `transactional_updater.go`: exclusive PID lock, same-filesystem staging, SHA-256/size verification, backup touched paths, durable phase journal, atomic file switch и post-apply verification.
- Ошибка на стадии commit/verifying автоматически восстанавливает все исходные файлы и удаляет newly-created targets; incomplete transaction после crash восстанавливается `update recover` или автоматически перед следующим apply.
- Source/destination symlink, path traversal, duplicate write/remove paths и изменение `.neverlauncher/updater` payload-ом блокируются fail-closed.
- `nl update apply|status|recover|self-test` предоставляет generic manifest update path и эксплуатационное восстановление; stale process lock определяется отдельно для Unix и Windows.
- `client install`, `client update`, `client repair`, `client rollback` и `client package-apply/package-consume` переведены на этот core; `client-state.json`, удаление obsolete managed files и rollback snapshot связаны с одной transaction boundary.
- Добавлены regression tests commit/delete, post-verify rollback, simulated crash recovery и traversal rejection; Windows amd64/arm64 и Linux arm64 cross-compilation проверяет platform-specific lock implementation.
- Native CI запускает реальный `update self-test` на Linux x64/ARM64, Windows и macOS. `release doctor`, strict preflight, repository policy и `release publish-check` для `0.15.6+` включают обязательный updater gate/self-test.

## 0.15.5 — Managed JRE Distribution

`0.15.5` добавляет production distribution Java 21 для Windows/Linux/macOS x64 и ARM64. Release использует точные Eclipse Temurin vendor archives, а NeverRuntime может устанавливать их из first-party local/HTTPS distribution manifest с fail-closed integrity checks. DB migration не требуется.

- Добавлен `scripts/release/managed-jre-distribution.py`: разрешение latest Temurin 21 JRE через Adoptium API, HTTPS-only download, проверка vendor SHA-256/size и реальной PE/ELF/Mach-O архитектуры `bin/java`.
- Vendor JRE archive не перепаковываются: `sourceSha256 == sha256`, поэтому upstream checksum сохраняется end-to-end.
- Добавлены `MANAGED_JRE_MANIFEST.json` и `MANAGED_JRE_EVIDENCE.json` для шести target: Windows/Linux/macOS × x64/ARM64.
- Добавлен `nl delivery verify-jre`; `release build/verify/publish-check` для `0.15.5+` требуют все шесть JRE archive и binding каждого artifact к `DELIVERY_MANIFEST.json`.
- NeverRuntime поддерживает `--manifest` / `NEVERLAUNCHER_MANAGED_JRE_MANIFEST`, локальный archive cache, exact SHA-256/size, safe archive paths, `javaEntry` и `java -version` verification, затем атомарную установку runtime. Remote manifest требует отдельный SHA-256 pin.
- Добавлен `.github/workflows/managed-jre-production-delivery.yml`, release staging через `NEVERLAUNCHER_MANAGED_JRE_ARTIFACTS_DIR`, offline regression gate и repository-policy checks.
- Direct Adoptium runtime acquisition сохранён как compatibility fallback, если Managed JRE Distribution не настроена.

## 0.15.4 — Notarized macOS x64 + ARM64

`0.15.4` переводит macOS delivery в dual-architecture Developer ID + Apple notarization production-контур. x64 и ARM64 собираются как отдельные thin Mach-O artifacts и не могут быть опубликованы без accepted notarization/stapled Gatekeeper-verifiable app. DB migration не требуется.

- Добавлен `scripts/release/build-macos-production.sh`: отдельные `x86_64-apple-darwin` и `aarch64-apple-darwin` CLI/Desktop/NeverGuard/NeverRuntime builds, Mach-O architecture checks, Hardened Runtime codesign и production Developer ID signing.
- Production signing использует `Developer ID Application` и secure timestamp; каждая architecture-specific `.app` проходит `xcrun notarytool submit --wait`, требует `Accepted`, затем `stapler staple`, `stapler validate`, `spctl --assess` и `codesign --verify --deep --strict`.
- Добавлены `MACOS_PACKAGE_MANIFEST_X64.json`, `MACOS_PACKAGE_MANIFEST_ARM64.json`, `MACOS_NOTARIZATION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json` с реальными SHA-256/size, CPU type, Team ID и notarization evidence.
- `nl delivery verify-macos --production` повторно проверяет thin Mach-O `CPU_TYPE_X86_64`/`CPU_TYPE_ARM64`, `LC_CODE_SIGNATURE`, package ZIP payload, embedded manifest, evidence и exact binding к `DELIVERY_MANIFEST.json`; на macOS дополнительно выполняются native codesign/stapler/Gatekeeper checks.
- `nl release build/verify` принимает ad-hoc candidate только для CI/regression, а `nl release publish-check` для `0.15.4+` fail-closed требует `developer-id-notarized` evidence для обеих архитектур.
- Добавлен отдельный `.github/workflows/macos-production-delivery.yml` с ephemeral keychain, внешним Developer ID P12 и App Store Connect API-key profile; signing credentials/private keys не включаются в release artifacts.
- Legacy `macos-universal` сохранён только как Guard CI certification input и исключён из publishable `DELIVERY_MANIFEST.json` для `0.15.4+`.

## 0.15.3 — Linux x64 + ARM64 production packages

`0.15.3` переводит Linux delivery в нативный dual-architecture production-контур. x64 и ARM64 собираются на соответствующих Linux runners, получают отдельные CLI/API/Desktop/NeverGuard/NeverRuntime binaries и deterministic tar.gz package. DB migration не требуется.

- Добавлен `scripts/release/build-linux-production.sh`: нативная сборка x64/ARM64 с fail-closed проверкой runner architecture.
- Добавлен `scripts/release/linux-package.py`: проверка ELF64 `e_machine`, реальные SHA-256/size и детерминированный tar.gz со встроенным package manifest.
- Добавлены `LINUX_PACKAGE_MANIFEST_X64.json`, `LINUX_PACKAGE_MANIFEST_ARM64.json`, `LINUX_PRODUCTION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json`.
- `nl delivery prepare-linux|verify-linux` и `nl release build/verify/publish-check` проверяют обе архитектуры, package payload, executable modes и binding к `DELIVERY_MANIFEST.json`.
- Publishable Linux naming теперь канонический `linux-x64`/`linux-arm64`; legacy `linux-amd64` сохранён только для Guard CI certification и исключается из delivery manifest 0.15.3+.
- Main CI собирает Linux x64 на `ubuntu-24.04`, ARM64 на `ubuntu-24.04-arm`, затем aggregate release импортирует exact outputs через `NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR`.
- `secret-scan.py` теперь проверяет не только ZIP, но и tar/tar.gz release packages.

## 0.15.2 — Signed Windows x64 + ARM64

`0.15.2` делает Windows delivery реальным dual-architecture production-контуром: x64 и ARM64 собираются отдельными native targets, подписываются Authenticode и не могут быть опубликованы без проверяемого RFC3161 timestamp evidence. DB migration не требуется.

- `build-windows-desktop.ps1` теперь собирает CLI, Desktop и NeverGuard отдельно для x64 (`x86_64-pc-windows-msvc`, PE `0x8664`) и ARM64 (`aarch64-pc-windows-msvc`, PE `0xAA64`), проверяя фактический PE Machine до и после signing.
- Production signing использует Windows SDK `signtool` с SHA-256 digest и RFC3161 `/tr` timestamp; каждый EXE после подписи проходит `signtool verify /pa /all` и `Get-AuthenticodeSignature`, включая exact signer и наличие timestamp certificate.
- Поддержаны внешний certificate-store thumbprint и ephemeral PFX import. PFX/private key не включаются в release artifacts; импортированный PFX certificate удаляется из `CurrentUser\My` даже при ошибке сборки.
- Добавлены канонические `neverlauncher-{cli,desktop}-windows-{x64,arm64}.exe`, `neverguard-windows-{x64,arm64}.exe`, отдельные ZIP/package manifests и `WINDOWS_SIGNING_EVIDENCE.json` с реальными hashes/sizes/signing metadata.
- `nl delivery verify-windows --production` проверяет x64+ARM64 evidence, PE architecture, Authenticode certificate table, package contents, package manifests, hashes/sizes, Guard delivery allowlist и exact binding к `DELIVERY_MANIFEST.json`.
- `nl release build/verify` проверяют structural Windows evidence для candidate; `nl release publish-check` для `0.15.2+` дополнительно требует production Authenticode evidence и fail-closed отклоняет `unsigned-development`.
- Aggregate release может импортировать отдельный post-signing Windows job через `NEVERLAUNCHER_WINDOWS_SIGNED_ARTIFACTS_DIR`. Legacy `windows-amd64` artifacts сохранены только как Guard CI certification aliases и исключены из публикуемого `DELIVERY_MANIFEST.json`.
- Добавлены Windows production GitHub Actions workflow, unit/regression tests и обязательный `signed-windows-x64-arm64-0152` smoke gate в CI/preflight/release doctor.

## 0.15.1 — Delivery Manifest + platform/architecture model

`0.15.1` начинает Production Delivery без декларативного каталога будущих сборок: release pipeline формирует `DELIVERY_MANIFEST.json` только из реально присутствующих файлов bundle и включает его в подписанный `SHA256SUMS`/Ed25519 boundary. DB migration не требуется.

- Добавлена каноническая delivery-модель `windows` / `linux` / `macos` и `x64` / `arm64` / `universal`; aliases `win32`, `darwin`, `amd64`, `x86_64`, `aarch64`, `universal2` нормализуются в одном runtime-коде. 32-bit/неизвестные targets отклоняются fail-closed.
- Каждый фактический delivery artifact получает component, format, canonical platform/architecture, SHA-256 и size. `publishedTargets` вычисляется из артефактов, а не задаётся вручную.
- `nl release build` для `0.15.1+` создаёт и сразу перепроверяет `DELIVERY_MANIFEST.json`; `nl release verify` повторно хэширует все записи и отклоняет missing/tampered artifact, path traversal, duplicate entries, non-canonical targets и рассинхрон `publishedTargets`.
- Добавлены рабочие команды `nl delivery target`, `nl delivery manifest`, `nl delivery verify` и `nl delivery resolve`. Resolver понимает macOS universal как совместимый с x64/ARM64 и не подменяет exact target нейтральным platform artifact при сортировке результатов.
- `DESKTOP_PACKAGE_MANIFEST.json` использует каноническое имя архитектуры `x64` вместо Go-специфичного `amd64`; имена существующих release-файлов остаются совместимыми.
- Production preflight, CI, `release doctor` и release-bundle publish gate требуют новый delivery gate; regression smoke собирает настоящий CLI, создаёт bundle, разрешает Windows ARM64 artifact и проверяет fail-closed tamper detection.

## 0.15.0 — ServerBridge 2 Release

`0.15.0` фиксирует ServerBridge 2 как production-релиз после протокола v2, Ed25519 node identities, одноразовых join tickets, Bukkit/proxy/Fabric/Forge/NeoForge runtimes, zero-patch topology/handoff, HA hardening и migration stabilization. Runtime-протокол остаётся v2; schema migration поверх `0030` не требуется.

- Production bridge build теперь завершается обязательной certification всех 11 platform-matched JAR: Velocity, BungeeCord, Waterfall, Bukkit, Spigot, Paper, Purpur, Folia, Fabric, Forge и NeoForge.
- Certification сверяет public matrix, `PLUGIN_MANIFEST.json`, фактические имена/содержимое JAR, `SHA256SUMS` и exact-version `BRIDGE_RELEASE_ALLOWLIST.json`; несовпадение или одинаковый artifact для разных платформ fail-closed.
- Folia и Fabric дополнительно проходят release-time descriptor checks (`folia-supported: true`, server-only/no-client-mod), а family runtimes проверяются по class entries внутри собранных JAR.
- `SERVERBRIDGE2_CERTIFICATION.json` включается в production bundle и обязателен для release-bundle/publish gate вместе с manifest и hash allowlist.
- Public ServerBridge matrix и все product metadata синхронизированы на `0.15.0`; API diagnostics публикуют релиз как `ServerBridge 2 Release`.

Migration: с `0.14.10` примените обычный release rollout без новой DB migration; перед publish соберите bridge artifacts production Gradle-сборкой и не публикуйте bundle без успешного `SERVERBRIDGE2_CERTIFICATION.json`.

## 0.14.10 — Migration + stabilization

`0.14.10` завершает линию ServerBridge 2 перед следующим feature-релизом: схема и runtime-поведение 0.14.1–0.14.9 сохранены, а migration/maintenance path стабилизирован для долгоживущих active/active инсталляций.

- Migration `0030_serverbridge_migration_stabilization_01410` безопасно seal-ит уже истёкшие active join tickets/handoffs, stale topology и expired signed nonces после остановленного/прерванного 0.14.9 maintenance pass.
- Maintenance больше не использует `ctid`-batch без row locks: bounded batches выбираются через `FOR UPDATE SKIP LOCKED`, поэтому housekeeping не ждёт обычные ticket/handoff write-транзакции и не создаёт лишнюю конкуренцию между API traffic и cleanup.
- Добавлена bounded retention-очистка terminal join tickets и handoffs. Consumed join сохраняется, пока связанная auth session активна, потому что он остаётся source proof для последующих proxy→backend handoff.
- Добавлены PostgreSQL indexes для consumed source-proof lookup, case-insensitive runtime backend-name resolution и terminal-row retention scans.
- Maintenance diagnostics теперь отдельно показывают количество удалённых terminal join tickets и handoffs.
- Exact `0.14.9 → 0.14.10` migration rehearsal проверяет сохранение Ed25519 identity epoch/status, cleanup expired nonce, sealing stale topology, наличие новых indexes и sealed migration checksum.
- Offline release gate и CI теперь включают `serverbridge-migration-stabilization-01410.py`; strict migration E2E включает полный 0.14.8 → 0.14.9 → 0.14.10 контур.

Migration: backup → остановить 0.14.9 API replicas → `nl db migrate apply` → `nl db migrate verify` (current: `0030_serverbridge_migration_stabilization_01410`) → запустить 0.14.10 replicas. Node identities, release hashes и действительные tickets/handoffs миграция не переписывает.

## 0.14.9 — Public ServerBridge Matrix + HA/hardening

`0.14.9` переводит ServerBridge 2 из single-instance-friendly режима в явно active/active-safe эксплуатацию и публикует каноническую матрицу всех 11 поддерживаемых bridge targets. Hot-path replay protection больше не выполняет глобальную очистку expired nonces; bounded cleanup выполняется отдельным maintenance pass под PostgreSQL advisory lock.

- Public `GET /api/v1/server-bridge/matrix` и `serverbridge/targets.json` используют один канонический capability set для Velocity/BungeeCord/Waterfall, Bukkit/Spigot/Paper/Purpur/Folia, Fabric, Forge и NeoForge.
- Topology status freshness-aware: edge активен только при свежем route observation и heartbeat обоих узлов.
- Добавлены PostgreSQL HA status, readiness/Prometheus gauges и диагностический maintenance snapshot.
- ServerBridge traffic получил отдельный Redis rate-limit budget, 64 KiB signed-body ceiling, header length validation, request deadline и no-store policy.
- Migration `0029_serverbridge_public_matrix_ha_hardening_0149` добавляет partial/freshness indexes без переписывания existing node identities/tickets/handoffs.
- Exact `0.14.8 → 0.14.9` migration rehearsal запускает реальный multi-instance PostgreSQL test: два repository handles соревнуются за один signed nonce, и принимается ровно один.

Migration: backup → `nl db migrate apply` → `nl db migrate verify`; затем запускайте 0.14.9 replicas с общими PostgreSQL/Redis и fail-closed rate limiting.

# Changelog

## 0.14.8 — Zero-patch installation + topology/handoff

`0.14.8` завершает ServerBridge 2 как drop-in integration: bridge artifacts не патчат `server.properties`, Paper/Spigot/Purpur/Folia/Fabric/Forge/NeoForge configs или proxy routing configs. Proxy-to-backend переход больше не пытается повторно использовать уже погашенный launcher ticket: Velocity/BungeeCord/Waterfall выпускают отдельный короткоживущий one-time handoff, а PostgreSQL хранит runtime-learned topology как source of truth.

- Migration `0028_zero_patch_topology_handoff_0148` добавляет PostgreSQL topology edges и one-time handoff credentials без переписывания существующих node identities/tickets.
- Handoff выпускается только активным proxy-kind после ранее успешно погашенного launcher ticket, пока исходная auth session остаётся активной и binding epoch совпадает.
- Target разрешается по canonical node ID или уникальному runtime backend name и должен быть backend-kind; handoff привязан к source/target Ed25519 identity epoch/fingerprint, project/profile/device/session и живёт не более 30 секунд.
- Target backend атомарно погашает handoff один раз; replay, target identity rotation, session/user revoke и permanent trust/integrity failure инвалидируют credential fail-closed.
- Создание handoff требует текущего разрешённого ServerBridge artifact integrity source proxy, а backend повторно применяет Device Trust, Minecraft integrity и собственный artifact integrity перед consume.
- Velocity создаёт handoff на `ServerPreConnectEvent`; BungeeCord/Waterfall используют cancel → async handoff → single reconnect, не блокируя proxy event loop.
- Zero-patch bootstrap создаёт только NeverLauncher-local comment/config scaffold при доступном writable plugin directory; read-only deployments продолжают работать через env/defaults и никогда не модифицируют Minecraft/proxy configuration.
- Добавлены runtime topology API, exact migration rehearsal `0.14.7 → 0.14.8`, PostgreSQL handoff E2E и обязательный offline release gate.

Migration: остановите 0.14.7 API instances, создайте backup, примените `0028_zero_patch_topology_handoff_0148` и убедитесь через `nl db migrate verify`, что она current. Обновите bridge artifacts до 0.14.8. Не включайте proxy forwarding/plugins patching специально для NeverLauncher: routing остаётся штатным для вашей платформы; ServerBridge изучает source→target edges при реальных handoff. Ed25519 enrollment и release-hash allowlist остаются обязательными security boundaries.

## 0.14.7 — Forge + NeoForge Server Bridge

`0.14.7` добавляет отдельные server-only ServerBridge-моды для Forge и NeoForge 1.21.1. Оба используют общий `modloader-family-common`, Ed25519 node identity, signed Protocol v2, PostgreSQL source of truth, release-hash integrity и one-time join tickets. Login блокируется до backend decision штатным `PlayerNegotiationEvent`, без post-login kick и без обязательного клиентского мода.

- Добавлены `neverlauncher-forge-bridge` и `neverlauncher-neoforge-bridge` с отдельными Gradle/platform metadata и отдельными integrity namespaces.
- Общий `modloader-family-common` выполняет self-measurement SHA-256, heartbeat, локальный Ed25519 key lifecycle и bounded async join validation.
- Forge/NeoForge login gate использует `PlayerNegotiationEvent.enqueueWork(Future)` и не блокирует server thread сетевым I/O.
- Migration `0027_forge_neoforge_server_bridge_0147` расширяет canonical `server_bridge_nodes_v2.kind` значениями `forge` и `neoforge`, сохраняя существующие identities/tickets.
- Production policy `0.14.7+` требует независимые `forgeSha256` и `neoforgeSha256`; hash одной платформы не авторизует другую.
- Full Minecraft E2E запускает Forge и NeoForge 1.21.1 и проверяет heartbeat, allow, replay deny, revoke и deny.
- Добавлены exact migration rehearsal `0.14.6 → 0.14.7`, backend regressions и обязательный offline release gate.

Migration: остановите 0.14.6 API instances, примените и проверьте `0027_forge_neoforge_server_bridge_0147`, обновите `BRIDGE_RELEASE_ALLOWLIST.json`, зарегистрируйте node как `kind=forge` или `kind=neoforge`, установите соответствующий JAR в `/mods` и enroll public Ed25519 identity. Private key остаётся только на сервере.
## 0.14.6 — Fabric Server Bridge

`0.14.6` добавляет server-only ServerBridge для Fabric 1.21.1 без обязательного клиентского мода. Мод использует Fabric login synchronizer как login gate, выполняет backend validation в bounded worker pool и сохраняет Ed25519 node identity, Protocol v2, PostgreSQL source of truth, release-hash integrity и one-time join tickets.

- Новый Loom-мод `neverlauncher-fabric-bridge` с `fabric.mod.json`, required Mixin accessor и server-only environment.
- Login validation запускается вне server tick; `ServerLoginNetworking.LoginSynchronizer.waitFor` не пропускает login до завершения backend decision. Deny применяется на Minecraft server executor.
- Artifact сам измеряет SHA-256, подписывает heartbeat/validate через локальную Ed25519 node identity и fail-closed работает при недоступности backend/integrity policy.
- Migration `0026_fabric_server_bridge_0146` расширяет `server_bridge_nodes_v2.kind` значением `fabric` без переписывания существующих identities/tickets.
- Release policy `0.14.6+` требует отдельный `fabricSha256`; Fabric JAR добавлен в release manifest/provenance и production verification.
- Full Minecraft E2E запускает реальный Fabric 1.21.1 server с Fabric API и проверяет heartbeat, allow, one-time replay deny, revoke и deny.
- Добавлены exact migration rehearsal `0.14.5 → 0.14.6`, backend kind/integrity regressions и обязательный offline release gate.

Migration: остановите 0.14.5 API instances, примените и проверьте `0026_fabric_server_bridge_0146`, обновите `BRIDGE_RELEASE_ALLOWLIST.json`, зарегистрируйте node с `kind=fabric`, установите `neverlauncher-fabric-bridge-0.14.6.jar` вместе с Fabric API на server и enroll public Ed25519 identity. Private key остаётся только на Fabric server.

## 0.14.5 — Proxy family: Velocity / BungeeCord / Waterfall

`0.14.5` объединяет proxy ServerBridge в production runtime для Velocity, BungeeCord и Waterfall без дублирования cryptographic/auth logic. Все три proxy используют Protocol v2, Ed25519 node identities, PostgreSQL source of truth, release-hash integrity enforcement и one-time join tickets.

- Добавлены `proxy-family-common` и `bungee-family-common`; Velocity переведён на общий runtime, BungeeCord/Waterfall получают отдельные platform-matched JAR.
- Proxy login validation выполняется вне event loop: Velocity через async `EventTask`, BungeeCord/Waterfall через `PreLoginEvent.registerIntent/completeIntent` и общий dedicated executor.
- BungeeCord/Waterfall runtime проверяет фактическую platform identity и fail-closed отклоняет неправильный JAR.
- PostgreSQL migration `0025_proxy_family_0145` расширяет `server_bridge_nodes_v2.kind` на `bungeecord` и `waterfall` без изменения существующих node identities/tickets.
- Release policy `0.14.5+` требует отдельные SHA-256 для Velocity, BungeeCord, Waterfall и всей Bukkit-family; release bundle содержит все восемь bridge JAR.
- Full Minecraft E2E запускает Velocity+BungeeCord+Waterfall+Spigot+Paper+Purpur+Folia и проверяет heartbeat, allow, one-time replay deny, revoke и deny.
- Добавлены exact migration rehearsal `0.14.4 → 0.14.5`, backend kind/integrity regressions и обязательный offline release gate.

Migration: остановите 0.14.4 API instances, примените и проверьте `0025_proxy_family_0145`, обновите `BRIDGE_RELEASE_ALLOWLIST.json`, затем установите строго platform-matched proxy JAR и зарегистрируйте node kind `velocity`, `bungeecord` или `waterfall`.

## 0.14.4 — Bukkit family: Bukkit / Spigot / Paper / Purpur / Folia

`0.14.4` переводит Bukkit-family ServerBridge из двух дублирующихся Paper/Purpur реализаций в один production runtime, собираемый отдельными platform artifacts для CraftBukkit/Bukkit, Spigot, Paper, Purpur и Folia. Все варианты используют ServerBridge Protocol v2, Ed25519 node identity, PostgreSQL source of truth, release-hash integrity enforcement и одноразовые join tickets из 0.14.1–0.14.3.

- Добавлен `bukkit-family-common`: единая login validation/heartbeat/config/identity/integrity реализация без копирования security logic между платформами.
- Добавлены реальные `neverlauncher-bukkit-bridge`, `neverlauncher-spigot-bridge` и `neverlauncher-folia-bridge`; Paper/Purpur переведены на тот же shared runtime.
- Runtime определяет фактическую платформу и fail-closed отключает JAR при mismatch, чтобы platform identity в Backend нельзя было подменить неправильным artifact.
- Folia artifact содержит `folia-supported: true`; heartbeat/network I/O выполняются отдельным daemon executor и не используют legacy Bukkit scheduler. Login enforcement остаётся в `AsyncPlayerPreLoginEvent`, где решение Backend должно быть получено до допуска игрока.
- PostgreSQL migration `0024_bukkit_family_0144` расширяет sealed `server_bridge_nodes_v2.kind` на `bukkit/spigot/paper/purpur/folia` без потери существующих node records.
- Release allowlist теперь содержит отдельные SHA-256 для всех шести bridge artifacts (Velocity + пять Bukkit-family JAR). Production config для release `0.14.4+` fail-closed требует `bukkitSha256`, `spigotSha256` и `foliaSha256` наряду с прежними hashes.
- Реальный Minecraft E2E в full mode запускает Velocity + Spigot + Paper + Purpur + Folia; Spigot/Folia проходят heartbeat и allow→revoke→deny login flow, а Paper сохраняет actual-client join coverage.
- Добавлены backend integrity/kind/manifest regressions, exact migration rehearsal `0.14.3 → 0.14.4` и обязательный offline release gate.

Migration: остановите 0.14.3 API instances, примените/проверьте `0024_bukkit_family_0144`, обновите `BRIDGE_RELEASE_ALLOWLIST.json`, затем установите artifact, соответствующий фактической платформе каждого node. На Folia используйте только `neverlauncher-folia-bridge-0.14.4.jar`.

## 0.14.3 — One-Time Join Tickets

`0.14.3` закрывает join authorization как самостоятельную одноразовую security boundary. ServerBridge ticket теперь генерируется из 192-bit CSPRNG, привязывается в PostgreSQL к exact Ed25519 `identity_epoch/key_fingerprint` узла и может быть атомарно погашен только один раз той же активной node identity.

- Migration `0023_one_time_join_tickets_0143.sql` добавляет versioned identity binding и persisted redemption proof (`redeemed_identity_epoch`, key fingerprint, SHA-256 signed-request nonce, IP). Active tickets 0.14.2 fail-closed инвалидируются при upgrade.
- `CreateServerBridgeJoinTicket` получает фактическую текущую identity под transaction/advisory lock; rotation между предварительной проверкой и issuance не позволяет выпустить ticket на retired key.
- Redemption выполняется одним conditional PostgreSQL `UPDATE ... WHERE status='active'` с проверкой ticket version, TTL, server id, issuance identity и текущей active node identity. Параллельный/replay validate получает отказ.
- Standard Minecraft/Yggdrasil `/join → /hasJoined` также переведён на consume-once: проверки IP/trust/integrity выполняются до погашения, затем первый валидный `/hasJoined` атомарно меняет `active → consumed`; повторный не авторизует игрока. Legacy ephemeral rows 0.14.2 очищаются на migration boundary.
- API возвращает `oneTime=true`, `ticketId`, `ticketVersion=2` и публичный issuance identity binding; внутренние access/session/device hashes в join response не раскрываются.
- Добавлены concurrency/replay regressions, exact migration rehearsal `0.14.2 → 0.14.3`, PostgreSQL redemption-proof E2E и обязательный offline release gate.

Migration: перед запуском 0.14.3 остановите 0.14.2 API instances, примените/проверьте `0023_one_time_join_tickets_0143`, затем выдавайте только свежие joins. Старые active authorizations намеренно не сохраняются через security boundary.

## 0.14.2 — Cryptographic Node Identities

`0.14.2` убирает shared ServerBridge bearer credential из production node-auth boundary. Velocity/Paper/Purpur создают локальную Ed25519 identity, Backend хранит только public key/fingerprint/epoch в PostgreSQL, а heartbeat/validate/has-joined/audit requests подписываются по canonical method/path/body SHA-256 с timestamp и single-use nonce.

- Добавлена синхронная API/CLI migration `0022_serverbridge_crypto_node_identities_0142.sql`: public identity material, `identity_epoch`, unique key fingerprint и PostgreSQL nonce replay store. Legacy 0.14.1 token hashes очищаются, active nodes становятся `identity-enrollment-required`, active join tickets инвалидируются.
- Node-auth headers: `X-NeverLauncher-Node-Id`, `X-NeverLauncher-Node-Key-Fingerprint`, `X-NeverLauncher-Node-Timestamp`, `X-NeverLauncher-Node-Nonce`, `X-NeverLauncher-Node-Signature`; подпись Ed25519 проверяется до разбора payload, timestamp допускает только bounded clock skew, nonce consume выполняется атомарно.
- `POST /api/v1/server-bridge/servers/{serverId}/rotate-identity` выполняет enrollment/rotation public key, увеличивает identity epoch, сбрасывает heartbeat/integrity state и инвалидирует незавершённые join tickets. Старый `/rotate-token` и `ServerToken` удалены из runtime/OpenAPI.
- Bridge plugins сохраняют private key только в локальном `node-identity.properties`, проверяют keypair/fingerprint при загрузке и подписывают каждый retry новым nonce.
- E2E переведён на реальное Ed25519 enrollment/signing; добавлен exact migration rehearsal `0.14.1 → 0.14.2` и mandatory offline release gate.

Migration: перед запуском 0.14.2 примените/проверьте `0022_serverbridge_crypto_node_identities_0142`. После upgrade установите bridge 0.14.2 и enroll его public key через `rotate-identity`; private key Backend не получает.

## 0.14.1 — ServerBridge Protocol v2 + PostgreSQL source of truth

`0.14.1` переводит ServerBridge из process-local/snapshot state в отдельный production persistence boundary. В PostgreSQL теперь хранятся node identity и server credential hash, plugin integrity/heartbeat state, short-lived join tickets и texture profiles; runtime JSON snapshot больше не является источником истины для ServerBridge при SQL repository.

- Добавлена синхронная API/CLI migration `0021_serverbridge_protocol_v2_0141.sql`: `server_bridge_nodes_v2`, `server_bridge_join_tickets_v2`, `server_bridge_textures_v2`, индексы и DB-level invariants Protocol v2.
- Join authorization стал одноразовым: активный ticket живёт 120 секунд и после успешных trust/integrity проверок атомарно переводится PostgreSQL `UPDATE ... WHERE status='active'` в `consumed`. Повторная server validation не авторизует игрока.
- Register/credential rotation и replace активного ticket сериализованы transaction-scoped advisory locks; rotation инвалидирует незавершённые tickets этого node.
- Velocity/Paper/Purpur bridge-клиенты отправляют `protocolVersion: 2` на heartbeat/validate. Backend возвращает `426 Upgrade Required` с `serverbridge_protocol_unsupported` для старого wire protocol.
- Legacy 0.14.0 snapshot импортирует только восстанавливаемые node metadata/textures. Поскольку plaintext credential и token hash намеренно не сериализовались, такой node получает `credential-rotation-required` и не может аутентифицироваться до административной ротации token; legacy active joins не переносятся.
- PostgreSQL mutation failures для integrity heartbeat и texture state теперь fail-closed, а не маскируются успешным API-ответом.

Migration: перед запуском 0.14.1 примените/проверьте `0021_serverbridge_protocol_v2_0141`. После upgrade зарегистрированные через snapshot nodes с `credential-rotation-required` необходимо один раз ротировать через административный ServerBridge endpoint.

## 0.14.0 — NeverGuard Release

`0.14.0` закрывает NeverGuard как production release boundary поверх уже реализованных Windows/Linux/macOS Guard, authenticated IPC v4, Integrity Evidence и server-verifiable Guard Attestation. Wire protocol не меняется: совместимость 0.13.x сохраняется на IPC v4, но Desktop теперь после authenticated handshake обязательно запрашивает MAC-protected `status` и fail-closed сверяет фактические `productVersion`, platform identity и protocol version Guard до допуска runtime.

- Backend использует Guard release policy **schema 2.0**: exact `NeverGuard SHA-256 + Desktop SHA-256` pair хранится внутри platform namespace (`windows`/`linux`/`macos`). Это устраняет декартово смешивание hashes из разных сертифицированных сборок и cross-platform reuse.
- Для Backend `0.14+` legacy flat allowlist отклоняется. Challenge и single-use launch ticket криптографически/сессионно связываются с release-policy schema, Guard protocol и trusted-device platform; live Minecraft/ServerBridge reevaluation применяет ту же exact-pair policy.
- Production policy требует `authenticode` для Windows и `developer-id-notarized` для macOS; Linux фиксируется как `integrity-only`. Windows artifact pairs дополнительно требуют `requireAuthenticode=true`.
- Platform package builders генерируют v2 fragments из фактических финальных binaries. `scripts/release/merge-guard-release-policy.py` объединяет только полный Windows+Linux+macOS production set и fail-closed отклоняет unsigned/ad-hoc fragments.
- Cross-platform Guard CI получает обязательный `neverGuardRelease0140`, проверяет v2 exact-pair metadata и фиксирует `releasePolicySchema=2.0` + authenticated release identity в certification evidence.
- Новый `neverguard-release-0140` gate включён в CI, strict preflight и `nl release doctor`.

Migration: database schema остаётся на sealed `0020`; 0.14.0 меняет release-policy/configuration boundary, а не persisted DB shape. Перед production rollout необходимо заменить `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` на объединённый policy v2 для 0.14.0.

## 0.13.10 — Migration, compatibility, stabilization

`0.13.10` закрывает upgrade/stability-контур NeverGuard после cross-platform certification 0.13.9. Релиз не добавляет новый Guard protocol: Windows/Linux/macOS остаются на authenticated IPC v4 и прежних attestation schemas, но persisted security state и release evidence получают fail-closed инварианты.

### Migration

- Добавлена синхронная API/CLI migration `0020_guard_migration_compatibility_stabilization_01310.sql`. Она не «чинит» неоднозначные security rows молча: upgrade останавливается, если `integrity_verified=true` имеет неполный/stale Guard snapshot либо `integrity_verified=false` содержит частичные Guard hashes/version/timestamp.
- После проверки migration закрепляет atomic shape/freshness constraints для `minecraft_sessions`: verified snapshot требует trusted device, четыре SHA-256, launcher version и timestamp в том же 90s ticket + 15s skew окне, которое проверяет runtime.
- `e2e/scripts/run-guard-migration-e2e.sh` материализует exact schema 0.13.9 (`0001..0019`), доказывает fail-closed отказ на partial snapshot, затем выполняет реальный `nl db migrate apply/verify` до sealed `0020` и проверяет DB constraints.

### Compatibility

- Исправлен platform parity bug: macOS trusted device теперь требует persisted Guard integrity не только на `guard-attest`/Minecraft session issuance, но и при последующей Minecraft/ServerBridge live reevaluation, как Windows и Linux.
- Guard protocol и platform attestation schemas не менялись, поэтому совместимые 0.13.9 runtime semantics сохранены; production allowlist по-прежнему является source of truth для разрешённых release hashes.

### Stabilization

- Per-platform `guard-ci-result.json` теперь криптографически/логически привязан не только к commit/run, но и к repository; aggregator и `nl release publish-check` отклоняют evidence, перенесённый из другого repository/fork.
- `nl release doctor` проверяет Compatibility, Device Trust и Guard target policies, а также новый 0.13.10 stabilization gate.
- Исправлен дублированный `steps:` в macOS GitHub Actions job, который делал workflow неоднозначным для YAML parsers.
- Добавлены regression tests для repository mismatch, macOS gameplay enforcement и migration catalog latest=`0020`.

### Проверено

- `python3 scripts/guard_ci/test_matrix.py`.
- `go test ./...` для CLI.
- `python3 scripts/smoke/offline/guard-migration-compatibility-stabilization-01310.py`.
- `python3 scripts/smoke/offline/repository-policy.py`, version alignment и canonical OpenAPI validation.
- Backend full `go test ./...` в текущей offline-среде требует уже закэшированные `pgx/mysql/x/crypto` modules; CI остаётся обязательным полным gate.

## 0.13.9 — Cross-platform Guard CI Matrix + release certification

`0.13.9` связывает уже реализованные Windows/Linux/macOS NeverGuard production-контуры с единым machine-verifiable release gate. PASS больше не выводится из наличия platform jobs или вручную записанного поля: каждая ОС публикует отдельный `guard-ci-result.json` для exact commit/run, aggregator повторно проверяет обязательные checks и SHA-256 артефактов, а `nl release publish-check` заново сверяет те же platform artifacts внутри финального release bundle.

### Cross-platform Guard CI matrix

- `guard-ci/targets.json` фиксирует три обязательных target: `guard-linux-amd64`, `guard-windows-amd64`, `guard-macos-universal`, runner/platform/arch и полный required check-set. Version manager синхронизирует `productVersion` этого policy-файла с корневым `VERSION`.
- Linux/Windows/macOS CI jobs после native tests и platform production gate создают `guard-ci-result.json` с exact source commit, Actions run ID, signing mode и SHA-256/size пяти объектов: platform package, Desktop, NeverGuard, package manifest и Guard release allowlist.
- Aggregate job fail-closed отклоняет missing/duplicate target, mismatched commit/run, ослабленный check-set, duplicate artifact filename или изменённый result evidence. Итоговые `GUARD_CI_TARGETS.json` и `GUARD_CI_MATRIX.json` являются CI evidence, а не вручную выставляемым статусом.
- CI certification намеренно не заявляет possession production vendor-signing credentials: Windows CI использует unsigned development package, macOS — ad-hoc CI signing, Linux — integrity-only mode. Production Authenticode/Developer ID/notarization остаются отдельными platform release requirements.

### Release certification

- `scripts/guard_ci/stage_release.py` переносит в release directory именно сертифицированные CI artifacts и перед копированием заново проверяет их size/SHA-256. Rebuild после matrix PASS не считается тем же evidence.
- `nl release build` для `0.13.9+` требует Guard matrix/targets и создаёт `GUARD_CI_CERTIFICATION.json`, который фиксирует policy, matrix digests и exact список certified platform artifacts.
- `RELEASE_MANIFEST.json` помечает `guardCICertified`, а все Guard evidence и Windows/Linux/macOS binaries/packages/manifests/allowlists входят в общий `SHA256SUMS`/Ed25519/provenance boundary.
- `nl release publish-check` повторно валидирует target policy, matrix, certification и хэширует каждый сертифицированный platform artifact из bundle. Post-CI replacement/tampering, даже при сохранённом JSON PASS, блокирует публикацию.
- Release builder для `0.13.9+` требует одновременно Compatibility, Device Trust и Guard certification evidence для publishable bundle; неполный набор остаётся только непубликуемым candidate.

## 0.13.8 — macOS production implementation

`0.13.8` добавляет отдельный production NeverGuard boundary для macOS вместо Linux-compatible fallback. Desktop запускает соседний universal Mach-O `neverguard`, взаимно аутентифицирует его по Unix-domain socket/HMAC protocol v4 и проверяет PID/UID peer credentials до выдачи integrity/attestation данных.

### macOS runtime boundary

- Desktop и NeverGuard применяют `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, private umask и очищают `DYLD_*`/`_XPC_DYLD_*` environment; Guard дополнительно ставит kqueue `EVFILT_PROC/NOTE_EXIT` watch на launcher parent. Ошибка hardening блокирует startup fail-closed.
- IPC создаётся только в приватном runtime directory, socket имеет mode `0600`, а peer PID/UID сверяются kernel credentials. Bootstrap secret передаётся только через inherited stdin и после handshake заменяется derived session key.
- Minecraft/Java запускается в отдельной process group; runtime policy и stop path управляют всей группой, чтобы дочерние процессы не переживали supervised primary process.
- macOS Integrity Evidence v1 измеряет SHA-256 Desktop/Guard Mach-O, PID/parent/UID/GID/process-group boundary и code-signing state. Отдельная macOS Guard Attestation фиксирует Hardened Runtime, library validation и runtime policy в server-challenge-bound digest.
- Backend проверяет отдельные macOS schemas, release SHA-256 allowlist, device signature, freshness/replay, UID/GID boundary, code signature, Hardened Runtime/library validation и все обязательные macOS process-policy flags.

### Signed and notarized production package

- `build-macos-desktop.sh` строит universal `arm64 + x86_64` Desktop/NeverGuard, подписывает их Developer ID Application с Hardened Runtime и формирует `.app`. Production build требует Team ID и `notarytool` profile, отправляет bundle на notarization, выполняет stapling и Gatekeeper assessment.
- `MACOS_PACKAGE_MANIFEST.json` фиксирует version/platform/protocol/hardening/Team ID; release Desktop до spawn Guard проверяет layout, ownership/permissions, expected code-signing identifiers, Team ID, Hardened Runtime, library validation, deep app signature и Gatekeeper/notarization status.
- Release build генерирует `GUARD_RELEASE_ALLOWLIST_MACOS.json` из SHA-256 финальных подписанных Mach-O. Ad-hoc signing разрешён только явным `--allow-ad-hoc` для CI/development и не проходит production package verifier.
- CI использует отдельный macOS native job: Rust fmt/test/clippy, подписанный Guard integration test и universal build. Offline gate `macos-production-implementation-0138.py` обязателен в repository policy/preflight.

Граница остаётся user-mode: root/kernel attacker и компрометация Developer ID ключа находятся вне локальной модели доверия. Удалённое решение всё равно принимает Backend по hardware/device-key signature, release allowlist и одноразовой Guard Attestation.

## 0.13.7 — Linux production implementation

`0.13.7` переносит NeverGuard production boundary на Linux как отдельную native-реализацию, а не как Windows-compatible stub. Desktop запускает соседний `neverguard` через приватный Unix-domain socket, взаимно аутентифицирует процесс bootstrap-secret/HMAC протоколом v4 и проверяет kernel peer credentials до любого integrity/attestation ответа.

### Linux runtime boundary

- NeverGuard и Minecraft runtime получают `PR_SET_PDEATHSIG=SIGKILL`, `PR_SET_NO_NEW_PRIVS=1`, отдельную process group и `RLIMIT_CORE=0`; Guard дополнительно отключает dumpability/ptrace exception и использует приватный umask. Ошибка применения/проверки блокирует launch fail-closed; stop/выход primary Java дополнительно завершает всю runtime process group.
- IPC размещается только в owner-only `XDG_RUNTIME_DIR/neverlauncher` (с безопасным fallback на `/run/user/<uid>`), socket создаётся с mode `0600`, а обе стороны проверяют PID/UID peer через `SO_PEERCRED`. Bootstrap secret по-прежнему передаётся только через inherited stdin и очищается после handshake.
- Linux Integrity Evidence v1 измеряет реальные ELF/executable SHA-256, `/proc/<pid>/status`, parent boundary, process start ticks и SHA-256 набора executable-backed mappings из `/proc/<pid>/maps`. Linux Guard Attestation включает отдельную process-policy schema и session-bound proof.
- Backend принимает Linux trusted devices в том же single-use challenge/ticket flow, но проверяет отдельные Linux schemas, UID/GID boundary, NoNewPrivs, dumpability/core/ptrace/PDEATHSIG state и release hashes. Authenticode на Linux не подменяется фиктивным trust result.

### Production package and CI

- `build-linux-desktop.sh` собирает side-by-side `neverlauncher-desktop + neverguard`, вычисляет SHA-256/size, создаёт `LINUX_PACKAGE_MANIFEST.json` и `GUARD_RELEASE_ALLOWLIST_LINUX.json`, затем формирует Linux production ZIP. Release Desktop до spawn Guard проверяет regular-file/symlink boundary, user-or-root ownership, write permissions, version/platform/protocol, IPC/hardening metadata и hashes.
- Linux NeverGuard integration test выполняет реальный Unix-socket handshake, process policy, Integrity Evidence и challenge-bound attestation. CI/preflight содержит обязательный `linux-production-implementation-0137.py`; release bundle обязан содержать Linux NeverGuard и allowlist.

Эта версия остаётся user-mode boundary: root/kernel attacker находится вне модели доверия. Backend release allowlist и hardware-bound device-key signature остаются обязательной удалённой точкой проверки.

## 0.13.6 — Windows production hardening

`0.13.6` переводит Windows NeverGuard boundary из функционального enforcement-контура 0.13.1–0.13.5 в более жёсткий production runtime. IPC protocol поднят до v4, Named Pipe получает explicit protected current-user/System ACL, Desktop удерживает NeverGuard в `KILL_ON_JOB_CLOSE` Job Object, а Desktop/Guard применяют fail-closed heap/DLL-search hardening до основной runtime-инициализации.

### Runtime and IPC hardening

- `HeapSetInformation(..., HeapEnableTerminationOnCorruption, ...)`, `SetDllDirectoryW("")` и `SetDefaultDllDirectories(APPLICATION_DIR | SYSTEM32)` обязательны для Windows Desktop/NeverGuard; ошибка блокирует startup.
- NeverGuard Named Pipe создаётся через explicit `SECURITY_ATTRIBUTES`/SDDL только для LocalSystem и object owner, дополнительно к local-only remote rejection и mutual HMAC. Protocol v4 включает hardening version/enforced и secure-ACL bit в authenticated ready proof.
- Desktop назначает NeverGuard в отдельный Job Object с `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` и проверяет membership до передачи bootstrap secret. Minecraft launch требует authenticated Guard, process policy, hardening state, secure ACL, lifetime job и production package verification.

### Release package hardening

- Release Desktop до spawn Guard читает соседний `WINDOWS_PACKAGE_MANIFEST.json`, отклоняет symlink/non-regular PE, проверяет version/platform/protocol и size/SHA-256 обоих executable. Release build записывает protocol v4 и hardening metadata.
- `build-windows-desktop.ps1` требует Authenticode для production по умолчанию (`-CodeSigningCertificateThumbprint ...`): Desktop/NeverGuard подписываются Authenticode перед hash manifest/allowlist, подписи повторно проверяются, а `authenticodeRequired` синхронизируется с Backend `requireAuthenticode`.
- Windows native integration test проверяет protocol v4, production-hardening state, secure pipe ACL и lifetime Job Object; новый offline gate `windows-production-hardening-0136.py` обязателен в CI/preflight.

Unsigned development package намеренно не проходит release-runtime Authenticode gate и предназначен только для CI/build validation.

Граница остаётся user-mode и не заявляет защиту от kernel/administrator attacker; server-side Guard Attestation, Minecraft/ServerBridge integrity enforcement и release allowlists продолжают применяться независимо.

## 0.13.5 — Minecraft/ServerBridge integrity enforcement

`0.13.5` переносит Guard Attestation из одноразового момента выдачи Minecraft token в live gameplay boundary. Integrity snapshot сохраняется вместе с Minecraft session, а каждый последующий token validation, Yggdrasil join/hasJoined и ServerBridge validate-join/has-joined повторно проверяет текущий Guard release allowlist. Удаление release hash из production policy немедленно отзывает уже выданные игровые credentials и связанные ServerBridge joins.

### Minecraft integrity persistence and live revocation

- Migration `0019_minecraft_serverbridge_integrity_0135.sql` сохраняет verified Guard attestation/evidence/release SHA-256, launcher version и verification time в `minecraft_sessions`; API и CLI используют идентичную sealed migration.
- `/api/v1/session/join` для Windows Guard-enforced device теперь обязан получить конкретный `minecraftAccessToken` и сохранить `minecraftSessionId`. Это закрывает прежний обход, при котором Never-session могла создать ServerBridge join без связи с Guard-verified Minecraft credential.
- Minecraft token validation, Yggdrasil join/hasJoined и ServerBridge validation заново сверяют snapshot с `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`. Release revocation действует на уже активные sessions без ожидания их TTL.
- Desktop передаёт только что выданный Minecraft access token в ServerBridge join до запуска Java, поэтому gameplay join связан с тем же device/session/binding epoch и Guard evidence, которые прошли Backend verification.

### ServerBridge artifact enforcement

- Velocity/Paper/Purpur вычисляют SHA-256 собственного запущенного JAR через `CodeSource` и отправляют его в heartbeat и каждый `validate-join`. При невозможности измерить JAR плагин fail-closed, когда `security.requireIntegrity=true` (production default).
- Backend принимает heartbeat только если `pluginVersion + serverType + pluginSha256` присутствуют в `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`. Accepted measurement сохраняется в ServerBridge state и повторно проверяется по текущему allowlist на каждом gameplay validation.
- `validate-join` обязан повторить тот же version/hash, что был подтверждён heartbeat. Ротация server token сбрасывает integrity measurement и требует нового heartbeat. Legacy/authlib `has-joined` также требует актуальный verified bridge measurement.
- `scripts/build/bridge-plugins.sh` строит реальные platform JAR, вычисляет их SHA-256, записывает hashes в `PLUGIN_MANIFEST.json` и генерирует `BRIDGE_RELEASE_ALLOWLIST.json`; release bundle включает оба файла. Production startup требует `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`.

ServerBridge JAR hash — application-level self-measurement, а не hardware/server attestation самого Minecraft-сервера: полностью скомпрометированный host с server token может подделывать пользовательский процесс. Enforcement предназначен для release allowlisting, accidental/unauthorized artifact drift и live backend policy, а не для утверждения kernel-level integrity удалённого сервера.

## 0.13.4 — Guard Attestation + Backend verification

`0.13.4` связывает локальный NeverGuard Windows boundary с Backend: сервер выдаёт persistent single-use challenge, отдельный `neverguard.exe` формирует свежую challenge-bound attestation поверх Integrity Evidence v1 и enforced process policy, а hardware P-256 device key подписывает каноническую привязку `user + device + session + bindingEpoch + release + attestation`. Backend пересчитывает evidence/attestation digests, проверяет device signature, freshness/replay и точные SHA-256 release binaries; только после этого выдаётся одноразовый короткоживущий Guard launch ticket, обязательный для Minecraft session в production.

### Guard-side attestation

- Authenticated IPC поднят до v3: request MAC теперь включает payload, а команда `guard-attestation` принимает server challenge только внутри уже аутентифицированной Desktop↔NeverGuard session. Guard заново собирает Integrity Evidence, прикладывает текущий enforced process-policy report и HMAC-привязывает attestation digest к IPC session.
- Canonical attestation фиксирует challenge hash/ID, evidence ID/digest, SHA-256 Guard/Desktop, module-set fingerprints, Authenticode results, process-policy flags и collection time. Desktop повторно проверяет challenge, evidence, policy, digest и session proof до использования результата.
- Windows integration test выполняет реальный handshake с `neverguard.exe`, получает challenge-bound attestation и проверяет связь с PID/process boundary.

### Backend verification and launch gate

- Добавлены `POST /api/v1/auth/devices/{deviceId}/guard-attest/begin|complete`. Challenge хранится в Repository, привязан к текущим `user/device/session/bindingEpoch/launcherVersion/keyFingerprint`, имеет TTL 90 секунд и потребляется атомарно.
- Complete требует hardware-bound P-256 trusted device с актуальной device attestation. Backend заново вычисляет Integrity Evidence SHA-256 и Guard Attestation SHA-256, проверяет freshness, parent boundary, enforced process policy, device signature и release allowlist.
- Успешная проверка выпускает persistent single-use Guard launch ticket с TTL 90 секунд. `/api/v1/minecraft/session` в production требует этот ticket и потребляет его атомарно; replay получает `412 Precondition Failed`.
- `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` обязателен в production. Windows release script формирует `GUARD_RELEASE_ALLOWLIST.json` из фактических SHA-256 `neverguard.exe` и Desktop executable; policy может дополнительно требовать trusted Authenticode.
- Это application-level server verification, а не TPM/Measured Boot quote и не kernel anti-cheat. Backend доверяет зарегистрированному hardware device key, challenge freshness, точным release hashes и evidence/policy, сформированным allowlisted NeverGuard/Desktop.

## 0.13.3 — Windows runtime/process policy enforcement

`0.13.3` переводит NeverGuard Windows policy из наблюдаемого evidence в реально применяемую runtime boundary. Политики включаются fail-closed: `neverguard.exe` усиливает собственный процесс до инициализации Tokio, а Java/Minecraft создаётся suspended и начинает выполнение только после успешного назначения в проверенный Windows Job Object.

### NeverGuard self-policy

- До создания async runtime NeverGuard применяет `SetProcessMitigationPolicy` для Dynamic Code, Extension Point Disable, Strict Handle Check, Image Load и Child Process policy, затем повторно считывает каждую policy через `GetProcessMitigationPolicy`. Ошибка применения или верификации завершает guard до открытия authenticated session.
- Guard запрещает dynamic code и создание дочерних процессов, отключает legacy extension points, включает strict-handle checks и блокирует remote/low-integrity image loading с предпочтением System32. Применённое состояние доступно через authenticated IPC `process-policy` и привязано к `ready` handshake.
- IPC protocol поднят до v2: ready proof теперь включает process-policy version/enforced bit, поэтому клиент не может принять старый guard как policy-enforced instance.

### Minecraft runtime tree enforcement

- NeverRuntime на Windows создаёт Java с `CREATE_SUSPENDED`. До выполнения пользовательского bytecode процесс назначается в новый Job Object с `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` и `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`. Breakaway flags запрещены и фактическая membership/limit mask проверяется Win32 API.
- Только после успешного `AssignProcessToJobObject` + `IsProcessInJob` + `QueryInformationJobObject` NeverRuntime находит suspended primary thread и вызывает `ResumeThread`. Любая ошибка до resume блокирует launch и инициирует termination child process.
- Job handle живёт столько же, сколько supervised runtime. Закрытие launcher/supervisor boundary завершает runtime tree через kill-on-close; `ProcessStatus` публикует фактически применённый `windowsProcessPolicy`.
- Запрет dynamic code намеренно не применяется к Java/Minecraft process: HotSpot JIT требует executable generated code. Вместо несовместимого флага runtime ограничивается Job Object/process-tree policy, а строгие mitigations применяются к самому небольшому NeverGuard process.

### Release verification

- Windows native test проверяет реальное создание suspended child, Job Object assignment, non-breakaway policy и resume; NeverGuard integration test проверяет authenticated process-policy report вместе с Integrity Evidence v1.
- CI/preflight получили обязательный `neverguard-process-policy-0133.py`; Windows job запускает policy unit/native tests, process-boundary integration test и `clippy -D warnings`.
- Это user-mode Windows process policy enforcement, а не kernel anti-cheat и не server-verifiable attestation. Оно не использует aggressive hooks и служит enforced runtime boundary для последующих NeverGuard integrity/attestation этапов.

## 0.13.2 — Windows Integrity Evidence v1

`0.13.2` добавляет первый рабочий Windows integrity-evidence слой поверх отдельного NeverGuard process boundary из `0.13.1`. Evidence собирается внутри `neverguard.exe` только после mutual-authenticated IPC и перед каждым Windows Minecraft launch; ошибка сбора, нарушение parent boundary, повреждённый digest или session proof блокируют launch.

### Evidence collection

- NeverGuard независимо сверяет фактический parent PID через Windows Toolhelp snapshot с PID, переданным Desktop, и завершает startup при mismatch. Это усиливает прежнюю проверку PID внутри handshake фактическим OS-observed parent relation.
- Для `neverguard.exe` и процесса launcher собираются image path, SHA-256 файла, размер/mtime и Windows process creation FILETIME. Хэш считается самим guard с диска, а не принимается от Desktop.
- Authenticode проверяется локальным `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` без UI и без сетевой загрузки revocation-данных; evidence сохраняет `trusted` и исходный WinTrust status code, поэтому unsigned/невалидный binary не маскируется как trusted.
- `GetProcessMitigationPolicy` снимает raw flags DEP, ASLR, Dynamic Code, Extension Point Disable, CFG, Binary Signature, Image Load, Child Process, User Shadow Stack и SEHOP. Неподдерживаемая отдельная policy попадает в `queryFailures`, сохраняя остальные evidence.
- Toolhelp module snapshot для guard и launcher превращается в детерминированный SHA-256 fingerprint набора загруженных module paths + SHA-256 содержимого каждого module file + file metadata; отдельно публикуются только basename нестандартных non-system modules, чтобы не раскрывать дополнительные пользовательские пути.

### Authenticated evidence transport

- Новый IPC command `integrity-evidence` доступен только внутри уже authenticated NeverGuard session. Сбор файлов/Win32 evidence выполняется через blocking worker, не блокируя Tokio IPC runtime.
- Canonical evidence core получает собственный SHA-256 (`evidenceSha256`). Guard дополнительно HMAC-привязывает digest к текущему IPC session key (`sessionProof`); Desktop заново проверяет schema/version, PID boundary, digest и proof constant-time перед возвратом evidence вызывающему коду.
- Desktop export-команда `neverguard_integrity_evidence` возвращает только уже локально проверенный payload. Windows `launch_minecraft` становится fail-closed на evidence collection/verification.

### Verification and security boundary

- Windows integration test запускает настоящий `neverguard.exe`, проходит handshake, получает Integrity Evidence v1, проверяет PID/hash/module/session-proof shape и затем корректный shutdown. Отдельные platform-independent unit tests защищают canonical evidence digest от незаметной модификации полей.
- CI/preflight получили обязательный gate `neverguard-integrity-evidence-0132.py`; Windows job компилирует и тестирует integrity implementation вместе с process-boundary integration test и clippy.
- Integrity Evidence v1 является **local Windows evidence**. `0.13.2` не объявляет его server-verifiable attestation, kernel anti-cheat, memory integrity proof или TPM-backed quote; cryptographic server verification остаётся отдельным следующим этапом NeverGuard.

## 0.13.1 — NeverGuard Windows: process boundary + authenticated IPC

`0.13.1` вводит первый production runtime boundary NeverGuard для Windows. Guard запускается отдельным `neverguard.exe` рядом с Desktop, а Windows launch становится fail-closed: Minecraft не стартует, пока Desktop не поднимет guard и не подтвердит authenticated IPC.

### Process boundary

- `neverguard.exe` является отдельным Rust process с собственным entrypoint; Desktop не загружает guard-код как hook/DLL в Minecraft-процесс.
- Desktop генерирует криптографически случайный 256-bit bootstrap secret и передаёт его guard только через унаследованный stdin. Secret не помещается в argv, environment, config или временный файл и zeroize-ится после handshake.
- IPC использует Windows Named Pipe в случайном per-launch namespace `NeverLauncher.Guard.*`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, один server instance и `PIPE_REJECT_REMOTE_CLIENTS`.
- Guard принимает только клиент с ожидаемым parent PID; знание PID не является аутентификацией и проверяется только вместе с possession bootstrap secret.

### Authenticated IPC v1

- Handshake взаимный: client/server nonces, HMAC-SHA-256 proofs в разных directions и отдельный derived session key. Transcript привязан к endpoint, обоим PID, guard start time и обоим nonce.
- После handshake каждый request/response имеет HMAC и sequence/request ID; guard отклоняет replay и out-of-order requests, malformed frame, protocol mismatch и MAC mismatch. Размер JSON frame ограничен 64 KiB.
- Реальные команды `ping`, `status`, `shutdown` проходят только после authentication. Потеря pipe завершает guard session; Desktop держит child handle с kill-on-drop.
- Windows integration test запускает настоящий `neverguard.exe`, проходит handshake/ping/status/shutdown и проверяет привязку к parent PID.

### Distribution and release gate

- `scripts/release/build-windows-desktop.ps1` собирает Desktop и NeverGuard release binaries, кладёт `neverguard.exe` рядом с Desktop, фиксирует SHA-256/size в `WINDOWS_PACKAGE_MANIFEST.json` и формирует Windows ZIP.
- Основной CI получил обязательный `windows-2022` job с real process integration test, clippy и сборкой side-by-side package; Linux release-candidate job зависит от успешного NeverGuard Windows job.
- Добавлен gate `neverguard-windows-0131.py`; он проверяет, что process/IPC/security/release wiring не заменены декларацией.

## 0.13.0 — Device Trust Release

`0.13.0` закрепляет Device Trust как release-level production boundary. Схема остаётся на sealed migration `0018_device_trust_stabilization_01210`: пустая migration ради номера версии не добавляется. Backend публикует machine-readable release contract через auth capabilities, а PostgreSQL E2E требует этот contract и `/ready` с актуальной migration перед lifecycle-проверками.

### Release certification

- Public Device Trust matrix теперь требует `deviceTrustRelease0130` на PostgreSQL protocol target и native Linux/Windows/macOS targets.
- Native evidence дополнительно запускает fail-closed key lifecycle test; protocol evidence проверяет runtime release contract, schema readiness и сохраняет их hash-verified evidence.
- CLI release pipeline получил `DEVICE_TRUST_TARGETS.json`, `DEVICE_TRUST_MATRIX.json`, `DEVICE_TRUST_CERTIFICATION.json`. Certification привязана к exact product version, source commit, Actions run ID и SHA-256 embedded targets/matrix.
- Начиная с `0.13.0`, `nl release publish-check` требует одновременно Minecraft Compatibility certification и Device Trust certification. Изменённая, неполная или относящаяся к другому commit trust matrix блокирует публикацию.
- `scripts/release/build-release.sh` принимает `NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE` / `NEVERLAUNCHER_DEVICE_TRUST_TARGETS_FILE`; CI bundle без публичного evidence остаётся release candidate и не считается официально publishable.

### Runtime boundary

- `/api/v1/auth/capabilities` и Desktop auth policy публикуют Device Trust Release contract: session↔device binding, device-bound refresh, risk enforcement, Minecraft/ServerBridge enforcement, permanent revoke/tombstones, dual-proof rotation и phishing-resistant recovery.
- Hardware boundary не переименована в vendor attestation: P-256 challenge-response по-прежнему означает proof-of-possession, а `vendorProvenance=not-remotely-verified`.
- Gate `device-trust-release-0130.py` запрещает пустую `0019`, проверяет migration parity, release certification code, runtime contract, public targets и обязательную CI/preflight интеграцию.

## 0.12.10 — Migration + stabilization

`0.12.10` стабилизирует накопленный Device Trust schema/runtime после `0.12.4–0.12.9` и делает upgrade с реальной `0.12.9` БД отдельным обязательным release invariant. Главная исправленная production-проблема: constraint `device_challenges_purpose_check`, созданный в `0.12.4`, не был расширен после появления `key-rotate`/`key-recover` в `0.12.8`, из-за чего PostgreSQL мог отклонять replacement challenge, хотя memory regression проходил.

### Schema stabilization

- Migration `0018_device_trust_stabilization_01210.sql` синхронно входит в API/CLI catalogs и расширяет challenge purpose до `register`, `session-bind`, `attest`, `key-rotate`, `key-recover`.
- Старые empty-string sentinels в `trusted_devices.replaced_by_device_id` и `minecraft_sessions.trusted_device_id` переводятся в SQL `NULL`; repository scanners/writers используют nullable SQL semantics.
- Валидные legacy revoked-device строки нормализуются в единое terminal state (`trust_state=revoked`, `attestation_state=revoked`, timestamp/reason); просроченные незавершённые challenge помечаются consumed.
- Перед установкой ограничений migration fail-closed проверяет cross-user replacement links, session/device ownership, binding shape и Minecraft session/profile/device ownership. Повреждённая или неоднозначная БД не «чинится» молча.
- После проверки устанавливаются ownership foreign keys и lifecycle/shape CHECK constraints для trusted devices, auth sessions и Minecraft trust snapshots. Replacement chain остаётся permanent tombstone и не может ссылаться на устройство другого пользователя.

### Upgrade E2E и release enforcement

- `e2e/scripts/run-device-trust-migration-e2e.sh` создаёт точную schema `0.12.9` (sealed migrations `0001..0017`), сеет допустимые legacy states, доказывает pre-upgrade failure `key-rotate`, затем запускает shipping CLI `nl db migrate apply/verify` и проверяет `0018` postconditions.
- Upgrade E2E требует, чтобы cross-user auth binding, replacement link и Minecraft device snapshot после migration отклонялись самой PostgreSQL БД.
- Production Device Trust E2E публикует upgrade evidence вместе с runtime evidence; public trust matrix требует `migrationStabilization01210`, поэтому PASS без проверенного `0.12.9 → 0.12.10` upgrade невозможен.
- Gate `device-trust-migration-stabilization-01210.py` включён в repository policy, CI и release preflight; strict Device Trust flow запускает migration E2E перед lifecycle E2E.


## 0.12.9 — Device Trust E2E + public trust matrix

`0.12.9` переводит Device Trust из набора отдельных regression/release gates в публично проверяемый end-to-end контур. Новый production E2E поднимает Backend с реальным PostgreSQL/Redis, применяет sealed migrations и проходит полный lifecycle device identity реальными Ed25519/P-256 подписями. PASS не хранится в репозитории: public trust matrix принимает только machine-verifiable evidence от exact Git commit и GitHub Actions run ID.

### Production Device Trust E2E

- `e2e/scripts/run-device-trust-e2e.sh` проверяет registration + single-use challenge replay deny, server-authoritative `binding_epoch`, device-bound refresh proof, ServerBridge trust before/after replacement, dual-proof key rotation, permanent old-key tombstone, persisted risk step-up, P-256 challenge-response attestation/replay deny, recovery deny без phishing-resistant step-up, успешный recovery после реальной WebAuthn P-256 registration/assertion ceremony и permanent revoke cascade.
- E2E использует production PostgreSQL repository с explicit `nl db migrate apply`/`verify`; runtime проверяет replacement chain непосредственно в PostgreSQL. Ed25519/P-256 device signatures и WebAuthn ES256 assertion создаются test-only OpenSSL helpers; private keys остаются только во временном runtime directory.
- Public evidence намеренно не содержит access/refresh tokens или private-key material; script fail-closed сканирует evidence перед публикацией. P-256 case подтверждает protocol proof-of-possession и явно фиксирует `vendorHardwareProvenance=not-verified`.

### Public Device Trust Matrix

- `device-trust/targets.json` задаёт четыре обязательных target без editable PASS/FAIL: PostgreSQL protocol E2E на Linux x86_64 и native Tauri/key-policy tests на Linux, Windows и macOS.
- `.github/workflows/device-trust.yml` генерирует dynamic matrix, собирает per-target `device-trust-result.json` и агрегирует `matrix.json`/`matrix.md` только при совпадении version, target, commit, run ID и checks; каждый evidence-файл обязан существовать и совпасть с зафиксированным SHA-256.
- Native targets компилируют Tauri key lifecycle и запускают security-policy unit tests, включая generation-scoped hardware labels, replacement payload, refresh binding и attestation payload. Матрица прямо указывает, что headless CI не является доказательством фактической работы OS secure storage/TPM/Secure Enclave на конкретном пользовательском устройстве.
- Gate `device-trust-e2e-matrix-0129.py` включён в repository policy, основной CI и preflight; strict preflight дополнительно запускает PostgreSQL Device Trust E2E.

## 0.12.8 — Cross-platform hardening + key recovery/rotation

`0.12.8` завершает lifecycle Device Trust для потери и плановой замены локального device key. Rotation сохраняет continuity только при одновременном proof-of-possession старым и staged-новым ключом. Recovery не требует утраченного private key, но требует свежий phishing-resistant account step-up и proof новым staged key. В обоих случаях Backend создаёт новую device identity, перепривязывает текущую session с новым `binding_epoch`, превращает старый fingerprint в permanent tombstone и отзывает credentials, связанные со старой identity.

### Runtime key lifecycle

- Desktop/Tauri использует двухфазный `stage → server ceremony → commit`: рабочий локальный ключ не заменяется до успешного server response; при ошибке до commit staged key удаляется, а после server commit staged metadata сохраняется для reconciliation.
- Hardware P-256 replacement больше не использует детерминированный label `backend+user`: каждый staged generation получает отдельный label, поэтому TPM/Secure Enclave key действительно меняется. Software Ed25519 replacement хранится отдельной staged записью OS keyring.
- Rotation подписывает один canonical `NeverLauncher Device Key Replacement v1` payload старым и новым ключом. Recovery требует свежий `phishing-resistant` step-up и подписывает тот же server-issued одноразовый challenge новым ключом.
- PostgreSQL replacement выполняется транзакционно: создаётся новый trusted device, текущая auth session получает новый device и `binding_epoch`, старая identity становится tombstone с replacement link, sibling sessions/refresh families/Minecraft sessions и незавершённые challenges отзываются. ServerBridge joins инвалидируются после commit.
- Ordinary registration из уже bound session запрещена: replacement нельзя обойти вторым ключом в той же доверенной session. Если server record исчез/отозван, Desktop больше не удаляет локальный ключ автоматически и переводит пользователя в recovery.
- Migration `0017_device_key_recovery_rotation_0128.sql` хранит replacement chain (`replaced_at`, `replaced_by_device_id`, `replacement_reason`) одинаково в API и CLI catalogs.

### Verification / release gates

- HTTP regressions проверяют обязательность old+new proof для rotation, fresh phishing-resistant step-up для recovery, permanent tombstone и запрет bypass через обычную регистрацию. Предыдущий Minecraft re-bind regression переведён на настоящий key-rotation flow.
- Gate `cross-platform-key-recovery-0128.py` подключён к preflight, repository policy и CI и проверяет backend transaction, migration parity, native staged-key lifecycle, Desktop reconciliation и реальные Go regressions.

## 0.12.7 — Minecraft / ServerBridge trust enforcement

`0.12.7` переносит Device Trust из launcher/auth boundary непосредственно в Minecraft gameplay boundary. Minecraft session и ServerBridge join теперь фиксируют server-authoritative snapshot `trusted_device_id + binding_epoch`, а последующая server-side проверка повторно сверяет его с текущей Never session, состоянием trusted device и risk decision. Поэтому старый Minecraft token или join нельзя продолжить использовать после re-bind, revoke или permanent risk transition.

### Runtime enforcement

- `POST /api/v1/minecraft/session` выдаёт официальный Minecraft credential только active Never session с verified bound device и допустимой risk policy. Persisted Minecraft session хранит device/binding snapshot через migration `0016_minecraft_serverbridge_trust_0127.sql`.
- Yggdrasil-compatible password authentication остаётся совместимым для старых клиентов, но `/sessionserver/session/minecraft/join` fail-closed требует verified bound device. Сам legacy opaque token больше не является обходом Device Trust.
- Minecraft validate/hasJoined и ServerBridge `validate-join`/`has-joined` повторно проверяют parent session/device/risk. `binding_epoch` mismatch, смена device, revoke/missing device или revoked risk делают credential непригодным; stale attestation и network-risk step-up дают временный deny до восстановления trust.
- Server-side validation намеренно не записывает IP/User-Agent game server как контекст игрока: risk observation происходит на launcher/player requests, а plugin/hasJoined только читает и применяет уже server-authoritative risk state.
- ServerBridge join дополнительно pin-ит `project/profile/channel`; plugin validation отклоняет `channel_mismatch` так же, как project/profile mismatch. Permanent trust failure инвалидирует join record немедленно.
- Velocity/Paper/Purpur получают конкретные trust reasons (`trusted_device_required`, `session_binding_changed`, `device_reattest_required`, `session_step_up_required` и другие) и показывают игроку соответствующее действие вместо общего deny.

### Verification / release gates

- HTTP regression tests покрывают unbound Minecraft denial, успешный bound credential, invalidation после re-bind, live ServerBridge risk deny и channel pinning.
- Minecraft E2E регистрирует реальный Ed25519 trusted-device key и подписывает production registration challenge перед server join; trust enforcement не обходится synthetic device metadata.
- Gate `minecraft-serverbridge-trust-0127.py` подключён к preflight, repository policy и CI и проверяет runtime, persistence, migration, plugin messages и regression coverage.

## 0.12.6 — Session ↔ Device binding + risk integration

`0.12.6` делает связь Never session с trusted device server-authoritative. Каждая session получает persistent `binding_epoch`; registration/re-bind атомарно увеличивает epoch, а Backend сравнивает его и `device_id/device_trust` с каждым access JWT. Поэтому access token, выпущенный до нового bind, больше не может продолжать работать только потому, что сама session ещё active.

### Device-bound refresh

- Refresh привязанной session требует proof текущим registered device key. Canonical `NeverLauncher Session Device Binding v1` payload связывает `user + session + device + binding_epoch` и SHA-256 текущего refresh token; сам refresh secret в подписываемый payload не включается.
- Backend сначала read-only проверяет refresh family/session binding и device signature, и только затем выполняет rotation. Wrong/missing device proof возвращает `428` и не расходует действительный refresh token. Replay уже consumed refresh token по-прежнему компрометирует всю family и отзывает replacement token.
- Desktop подписывает refresh внутри отдельной Tauri IPC-команды `sign_session_refresh`; команда сама строит canonical payload и сверяет local persisted `deviceId`, поэтому React не может использовать её как arbitrary signing primitive. Software Ed25519 и hardware P-256 используют уже зарегистрированный ключ.

### Risk enforcement

- Migration `0015_session_device_risk_0126.sql` добавляет `binding_epoch`, `risk_score`, `risk_action`, `risk_evaluated_at`; API/CLI migration catalogs синхронизированы. Risk actions: `allow`, `step-up`, `reattest`, `revoke`.
- IP/User-Agent drift становится `step-up`; stale hardware attestation — `reattest`; missing/revoked/invalid trusted device и refresh-token reuse ведут к `revoke`. `risk_updated_at` меняется только при изменении решения, поэтому успешный step-up не становится немедленно устаревшим из-за очередной оценки.
- Sensitive handlers через `requireFreshAuth117` теперь проверяют risk action до обычной freshness policy. Step-up очищает network-drift reasons; hardware attestation completion снимает `reattest` после повторной server-side проверки device state.
- E2E покрывает invalidation pre-bind JWT, mandatory bound-refresh proof, wrong-proof non-consumption, refresh replay family compromise, persisted risk decision и secret-free canonical payload. Gate `session-device-risk-0126.py` подключён к preflight, repository policy и CI.

## 0.12.5 — Device Management + Revocation

`0.12.5` превращает существующий device revoke из разрозненной операции в единый production lifecycle. Пользователь видит active/revoked trusted devices, текущее устройство, может переименовать устройство, необратимо отозвать одно устройство или атомарно отозвать все остальные. Администратор получает тот же registry и revoke после fresh phishing-resistant step-up.

### Runtime revocation

- PostgreSQL revoke выполняется одной транзакцией: trusted device становится permanent tombstone, свежая attestation снимается, незавершённые device challenges расходуются, связанные Never sessions, refresh-token families/tokens и Minecraft sessions отзываются. Возвращаются фактические счётчики, а не результат повторного in-memory revoke.
- ServerBridge joins для затронутых Never sessions инвалидируются немедленно. Access JWT перестаёт проходить session observation после server-side revoke; refresh family также больше не может ротироваться.
- `POST /api/v1/auth/devices/{deviceId}/revoke` и `POST /api/v1/auth/devices/revoke-others` дают явный management API; прежний `DELETE` сохранён как совместимый revoke. `revoke-others` разрешён только session, уже связанной с active verified trusted device, и сохраняет именно это текущее устройство.
- Revocation необратим для прежнего device key/fingerprint: повторная регистрация отозванного ключа запрещена, повторный revoke идемпотентен. Для повторного подключения установка должна создать новый device key.

### Clients / operations / gates

- Desktop показывает trusted-device registry, current/revoked state, rename/revoke/revoke-others. При self-revoke удаляются локальный device key и сохранённая auth session из OS secure storage.
- Admin UI показывает trusted devices и выполняет permanent revoke через защищённый admin endpoint; критическая операция остаётся за fresh phishing-resistant step-up.
- HTTP E2E проверяет challenge invalidation, access/refresh cutoff, tombstone re-enrollment denial, self-revoke и idempotency. `device-management-revocation.py` включён в preflight, repository policy и CI. Новая DB migration не требуется: schema 0.12.4 уже содержит необходимые trusted-device/session/challenge поля; 0.12.5 меняет runtime semantics и transaction boundaries, а не добавляет пустую schema-заготовку.

## 0.12.4 — Challenge-response attestation

`0.12.4` добавляет отдельную рабочую attestation-церемонию поверх hardware-bound identity из `0.12.3`. Backend выдаёт короткоживущий single-use challenge только сессии, которая уже доказала владение зарегистрированным P-256 hardware key и привязана к тому же trusted device. Native Desktop подписывает отдельный canonical `NeverLauncher Device Attestation v1` payload тем же non-exportable platform key; software Ed25519 fallback к этой IPC-команде не допускается.

### Attestation lifecycle

- Добавлены `POST /api/v1/auth/devices/{deviceId}/attest/begin|complete`. Challenge persistent, привязан к `user + device + session + fingerprint + algorithm + binding + provider`, имеет TTL 2 минуты и расходуется атомарно до проверки подписи, поэтому replay и повтор после неверного proof отклоняются.
- Успешный proof сохраняет `attestation_state=verified`, `attestation_method=challenge-response-v1`, `attested_at`, `attestation_expires_at` и device assurance `challenge-response-attested`. Freshness window — 12 часов; после истечения API/JWT эффективно возвращаются к `proof-of-possession`, пока ceremony не выполнена снова.
- Access JWT и `/api/v1/auth/device-trust` отражают свежий attestation state. Это диагностический device assurance: он не повышает RBAC, MFA/auth strength и не считается phishing-resistant user authentication.
- Desktop автоматически выполняет attestation после registration/session-bind только для `p256/hardware`. Новый native `attest_device_payload` принимает исключительно canonical attestation payload, сверяет user/device/fingerprint/provider и не имеет software/create fallback.

### Security boundary / persistence

- Migration `0014_challenge_response_attestation_0124.sql` добавляет persistent attestation state/freshness, расширяет допустимый device assurance и разрешает purpose `attest` в существующем single-use challenge registry. Backend и CLI catalogs byte-identical.
- Challenge-response подтверждает свежое владение уже зарегистрированным hardware-bound key. Текущий platform signer не предоставляет NeverLauncher проверяемый vendor TPM quote / Secure Enclave attestation certificate, поэтому `hardwareProvider` не объявляется remote provenance; API явно возвращает `hardwareProvenance=not-remotely-verified`.
- HTTP E2E проверяет success, unbound-session rejection, replay, wrong-signature consumption и software-key rejection. Новый offline gate `challenge-response-attestation.py` включён в preflight и CI.

## 0.12.3 — Hardware-bound identities

`0.12.3` добавляет реальный hardware-backed device-key path поверх Device Trust Core. Desktop сначала пытается создать non-exportable P-256 signing key в platform hardware provider (Secure Enclave / TPM). Если platform signer сообщает keyring/software/test backend, он не считается hardware-bound: клиент явно остаётся на существующем Ed25519 + OS secure storage пути.

### Hardware identity lifecycle

- Tauri использует pinned `hardware-enclave 0.2.10` и P-256 ECDSA. Hardware private key не сериализуется в NeverLauncher metadata/keyring record и не пересекает IPC; сохраняются только public SEC1 key, SHA-256 fingerprint, provider name и platform key label.
- Device Trust protocol теперь принимает `ed25519/software` и `p256/hardware`. Для P-256 Backend проверяет uncompressed SEC1 public key и raw IEEE P1363 `r||s` signature над тем же canonical single-use challenge payload.
- Hardware key автоматически используется в registration/session-bind flow официального Desktop. Если HSM недоступен, fallback остаётся явным `keyBinding=software`, без ложного hardware status.
- Delete/reset удаляет platform hardware key и локальную metadata; existing `0.12.2` Ed25519 records автоматически продолжают работать как software-bound identities.

### Server boundary / migration

- Добавлена migration `0013_hardware_bound_identities_0123.sql`: `trusted_devices.key_binding`, `hardware_provider`, поддержка `key_algorithm=p256`, relational CHECK constraints и индекс по binding state. Backend/CLI catalogs byte-identical.
- Access JWT содержит диагностические `device_key_binding` и `device_hardware_provider` для уже verified device. Эти claims **не** используются для RBAC, MFA strength или step-up decisions.
- `keyBinding=hardware` в `0.12.3` означает локально выбранный non-exportable hardware provider, но ещё не remote attestation. Поэтому server-side `assurance` остаётся `proof-of-possession`. TPM/Secure Enclave attestation/challenge-response verification является отдельным следующим Device Trust этапом.

### Release gates

- HTTP E2E выполняет реальный P-256 registration + second-session bind и проверяет, что hardware metadata не повышает assurance.
- Добавлен `hardware-bound-identity.py`; preflight/repository policy/CI требуют HSM path, P-256 verifier, migration `0013`, запрет keyring/software promotion и Linux TPM build dependency.

## 0.12.2 — Device keys + OS secure storage

`0.12.2` переводит Device Trust из server-only proof API в рабочий Desktop lifecycle. Официальный Tauri-клиент сам создаёт Ed25519 device key, хранит private seed только в native OS credential store и автоматически выполняет registration/session-bind proof после Never login.

### Device key lifecycle

- Добавлен Tauri-модуль `device_keys`: Ed25519 key generation через OS CSPRNG, deterministic per-backend/per-user keyring namespace, self-check public key/fingerprint и zeroization временного seed/serialized secret.
- Windows использует native credential manager, macOS — Keychain, Linux — Secret Service через `keyring`; plaintext/file/localStorage fallback отсутствует.
- Private key не передаётся React и Backend. IPC возвращает только public key/fingerprint/device id и detached signature конкретного server challenge.
- Auth session record получил canonical `userId`, чтобы device key namespace не зависел от изменяемого email. Старые сохранённые sessions восстанавливают `userId` из уже проверенного JWT `sub`.
- После login Desktop автоматически выполняет `register/begin → local Ed25519 sign → register/complete`; на следующих sessions используется `verify/begin|complete`. Обновлённый verified-device access token атомарно заменяется в OS credential store.
- Если локальная привязка указывает на отозванный/удалённый server device, Desktop создаёт новую local device identity. Fingerprint conflict после прерванной регистрации также fail-closed разрешается новой key pair, а не повторным использованием неизвестной server binding.
- Logout удаляет session secrets, но сохраняет device key для следующего proof-of-possession.

### Release gates

- Добавлен `scripts/smoke/offline/device-key-storage.py`; обычный preflight проверяет наличие native key generation/keyring/signing path и запрещает появление private device key material в React/localStorage.
- Repository policy закрепляет Tauri commands и automatic Desktop proof flow как обязательную часть `0.12.2`.
- `proof-of-possession + OS secure storage` всё ещё не объявляется hardware-bound identity: TPM/Secure Enclave/Windows Hello/Keychain access-control attestation относятся к следующим Device Trust этапам.

## 0.12.1 — Device Trust Core + device registry

`0.12.1` вводит первую рабочую границу Device Trust поверх стабильного Auth Federation release. Старое поле session `deviceId` остаётся недоверенной клиентской меткой для совместимости; доверенная device identity создаётся только после Ed25519 proof-of-possession и хранится отдельно в persistent registry.

### Device registry / proof-of-possession

- Добавлен persistent `trusted_devices` registry с canonical `device id → user`, Ed25519 public key, SHA-256 fingerprint, platform/client metadata, status/trust state, first-class revoke metadata и timestamps последней успешной криптографической проверки.
- Регистрация устройства — реальная challenge-response ceremony: Backend создаёт short-lived single-use challenge, клиент подписывает канонический payload Ed25519 private key, Backend проверяет подпись и только после этого создаёт trusted device. В БД хранится только public key; private key никогда не передаётся Backend.
- Challenge хранится persistent в `device_challenges`, привязан к `user + device + purpose + session`, расходуется атомарно и не может быть replayed. Истёкшие/старые consumed challenges очищаются при записи новых.
- `assurance=proof-of-possession` сознательно не называется hardware-bound: привязка к TPM/Secure Enclave/OS secure storage относится к следующим Device Trust версиям.

### Session binding / revocation

- `auth_sessions.device_id` не переосмысляется как trusted identity. Добавлены отдельные `trusted_device_id`, `device_trust_state` и `device_verified_at`.
- После регистрации или повторного proof текущая Never session криптографически связывается с registry device. Обновлённый access JWT получает `device_id`, `device_trust` и `device_verified_at`.
- Повторная сессия может доказать владение уже зарегистрированным device key через `verify/begin|complete`; challenge дополнительно привязан к конкретной Never session.
- Revoke устройства переводит device в `revoked` и отзывает все связанные Never sessions и refresh-token families; связанные session risk state становятся `compromised`.
- Пользователь может list/rename/revoke свои устройства, администратор — фильтровать registry и выполнять revoke после свежего phishing-resistant step-up.

### Migration / release gates

- Добавлена migration `0012_device_trust_core_0121.sql`: `trusted_devices`, `device_challenges`, session trust columns, relational FK/check constraints и индексы.
- Backend и CLI migration catalogs содержат byte-identical `0012`.
- HTTP E2E проверяет login → registration challenge → Ed25519 proof → trusted session → second-session proof → challenge replay rejection → device revoke → session/refresh-family invalidation.
- OpenAPI и repository policy считают device registry, proof path и migration обязательными `0.12.1` release gates.

## 0.12.0 — Auth Federation Release

`0.12.0` завершает линию Auth Federation `0.11.1–0.11.10` как стабильный production release. Local, SQL, HTTP, OIDC и Microsoft являются providers одного Federation Core; passkeys/TOTP/recovery применяются как auth methods/MFA поверх canonical Never user, а Minecraft Auth Adapter получает уже каноническую Never session независимо от источника входа.

### Stable federation boundary

- Production startup использует стабильный `NewFederationCore(...)`; versioned constructors оставлены только для source compatibility. Встроенный `local` provider теперь проходит тот же Connector SDK conformance gate, что SQL/HTTP/OIDC/Microsoft.
- Добавлены provider-agnostic explicit-link endpoints `POST /api/v1/auth/providers/{providerId}/link/begin|complete`. Любой `browser-auth` connector может быть связан с уже аутентифицированным Never user по доказательству provider identity; совпадение email не является доказательством и не запускает auto-link.
- `GET /api/v1/admin/auth/federation/status` показывает health/capabilities/provisioning policy и количество linked identities для каждого provider. `/ready` дополнительно проверяет, что в registry есть хотя бы один реально здоровый authentication provider.
- External provider token остаётся только server-side credential: он не становится Never access/refresh token и не возвращается из linking/login API.
- Session issuance больше не создаёт `local` identity как побочный эффект. Passwordless passkey создаёт canonical session с `provider=passkey` и без фиктивной `identity-local-*`; MFA continuation после SQL/HTTP/OIDC/Microsoft сохраняет исходные provider/identity. Local identity принадлежит только реальному local-password lifecycle.

### Release migration / canonical local identity

- Добавлена migration `0011_auth_federation_release_0120.sql`. Она backfill/normalize canonical `local` identities для password-capable users и fail-closed отклоняет non-canonical provider/subject values.
- PostgreSQL constraint triggers гарантируют invariant: пользователь с локальным password hash обязан иметь `local` identity с `subject == user.id`; такую identity нельзя удалить/повредить, пока пароль активен.
- Bootstrap admin и `SetUserPassword` теперь транзакционно создают/обновляют local identity. Это закрывает обход Federation Core для первоначальной установки и для добавления локального пароля external-only пользователю.
- Backend и CLI содержат byte-identical migration catalog `0001–0011`; PostgreSQL federation E2E дополнительно проверяет применение `0011` и local-identity invariant.

### Stable release gates

- Federation E2E больше не привязан к конкретной milestone-версии: report schema стабилизирован отдельно от `toolVersion`, поэтому тот же gate применяется к `0.12.x` без изменения тестовой семантики.
- Release matrix включает generic explicit linking/runtime provider health наряду с Local/SQL/HTTP/OIDC/Microsoft/passkey, refresh replay, multi-instance PostgreSQL и Minecraft session exchange.
- OpenAPI и repository policy проверяют stable federation routes, canonical registry и release migration как обязательные `0.12.0` gates.

## 0.11.10 — Federation E2E + migration + stabilization

`0.11.10` не добавляет новый authentication provider: релиз превращает Federation Core `0.11.2–0.11.9` в исполняемо проверяемый release gate. Local, SQL, HTTP, OIDC, Microsoft и passkey проходят одну canonical session/Minecraft matrix; production PostgreSQL E2E проверяет restart/multi-instance refresh/revoke/replay, а migration tooling теперь fail-closed обнаруживает downgrade, checksum drift и незапечатанные legacy migration records до изменения схемы.

### Federation release gates

- `scripts/test/federation-e2e.py` запускает реальную connector/federation matrix: Local, SQL, HTTP, OIDC, Microsoft, passkey, canonical/JIT identity rules, Minecraft session exchange и security failure cases. Это release test, а не manifest/endpoint declaration.
- `e2e/scripts/run-federation-postgres-e2e.sh` поднимает PostgreSQL/Redis и три Backend instances. Test выполняет login на A, restart A, refresh после restart, refresh на B, validation на C, replay старого refresh token на C и проверяет отзыв family на A/B/C.
- CI запускает обе матрицы; strict preflight дополнительно включает PostgreSQL multi-instance E2E через `NEVERLAUNCHER_PREFLIGHT_FEDERATION_POSTGRES=1`.
- Federation provider registry больше не сообщает устаревшую внутреннюю версию: runtime metadata использует текущую `VERSION`.

### Migration / upgrade stabilization

- Добавлена migration `0010_federation_stabilization_01110.sql`. Перед добавлением constraints она fail-closed проверяет существующие session/refresh/provider-credential данные; повреждённая БД не «лечится» молча.
- Усилена целостность refresh-token families: допустимые state значения, не более одного `current` refresh token на family, согласованность `session/user/family` и deferrable consistency foreign keys для транзакционной rotation.
- Provider credentials теперь дополнительно связаны composite FK с canonical `auth_identity`, поэтому credential не может принадлежать другому user/provider/subject.
- `nl db migrate apply` сначала проверяет unknown/future migrations и checksum drift. Blank checksum старой известной migration может быть безопасно запечатан текущим embedded checksum; несовпадающий checksum блокирует upgrade.
- Добавлен `nl db migrate verify`: проверяет, что schema полностью применена, нет unknown migrations, нет blank checksum и каждый checksum совпадает с binary catalog.
- Backend migration status возвращает `compatible`, `unknown` и `unverified` наряду с current/pending, чтобы upgrade tooling мог отличить pending upgrade от unsafe schema state.
- Embedded CLI и Backend migration catalogs остаются byte-identical; repository policy проверяет это как release gate.

### Stabilization / failure matrix

- Release matrix отдельно проверяет OIDC issuer/audience errors, HTTP signature/replay/SSRF, Microsoft tenant/signing-key confusion, WebAuthn wrong-origin/challenge replay, SQL disabled/TLS/read-only behavior, refresh replay и canonical identity reassignment protection.
- PostgreSQL E2E делает `db migrate verify` до запуска Backend и после replay/multi-instance сценария, поэтому успешный auth test одновременно подтверждает restart-safe schema state.
- Новых пользовательских auth semantics в `0.11.10` нет: external provider token по-прежнему не является Never token, Minecraft session остаётся дочерней к Never session, а account linking не происходит по одному совпавшему email.

## 0.11.9 — Minecraft Auth Compatibility 2.0

`0.11.9` отделяет Minecraft identity/session от способа входа в NeverLauncher. После local/SQL/HTTP/OIDC/Microsoft/passkey authentication канонический Never user получает persistent Minecraft profile и отдельный opaque Minecraft session token; Minecraft-слой больше не проверяет локальный password hash и не использует Never JWT как игровой access token.

### Minecraft identity / session adapter

- `minecraft_profiles` хранит стабильный UUID, производный только от immutable canonical Never user ID. Email/provider subject не участвуют в UUID; созданное Minecraft name также остаётся стабильным при изменении профиля пользователя.
- `POST /api/v1/minecraft/session` обменивает уже аутентифицированную Never session на отдельную Minecraft session. Opaque `nlmc_*` token хранится только как SHA-256 hash, связан с parent Never session и автоматически перестаёт быть действительным после её revoke/logout.
- Persistent `minecraft_sessions` и short-lived `minecraft_joins` работают между Backend instances. Yggdrasil refresh потребляет старый token; повторный refresh отклоняется. `hasJoined` повторно проверяет Minecraft session и parent Never session и при переданном `ip` проверяет его против join request.
- `profile:launch` достаточно для session exchange: обычный player не нуждается в admin/project-read permission.

### Yggdrasil / Desktop / NeverRuntime

- Реально зарегистрированы `/authserver/authenticate|refresh|validate|invalidate|signout`, `/sessionserver/session/minecraft/join|hasJoined`, profile lookup и `/api/profiles/minecraft/{username}`. Password-capable providers проходят Federation Core; passkey/OIDC/Microsoft используют Never-session exchange.
- Root metadata совместим с authlib-injector. NeverRuntime автоматически добавляет подписанный `authlib-injector*.jar` из release manifest как `-javaagent` к текущему Backend; произвольный локальный JAR таким образом не принимается.
- Desktop перед launch получает Minecraft session и передаёт NeverRuntime реальный UUID/access token вместо `offline` и нулевого UUID. Token редактируется в command preview/diagnostics. ServerBridge join использует то же canonical Minecraft profile name.
- Microsoft sign-in по-прежнему не считается доказательством Minecraft ownership; `0.11.9` реализует Never-managed Minecraft compatibility identity/session, а не Mojang/Microsoft entitlement bypass.
- Встроенная migration chain `nl db migrate apply` синхронизирована с Backend migrations `0001–0009`; repository policy теперь fail-closed проверяет одинаковый набор файлов и SHA-256 содержимого, чтобы manual production upgrade не отставал от Backend auto-migrate.

## 0.11.8 — Session Management 2.0

`0.11.8` переводит Never sessions на полноценный production session-management контур: стандартные JWT/JWS access tokens с `iss`/`aud`/`sub`/`sid`/`jti`/`iat`/`exp`/`kid`/`auth_time`/`amr`, rotation-capable signing keyring, persistent device/risk metadata и пользовательские/административные session controls. Refresh-token family replay по-прежнему отзывает всю family и теперь явно переводит сессию в `compromised`.

### Sessions / risk / controls

- PostgreSQL остаётся source of truth для sessions и refresh families; сохраняются identity/provider, device, first/last IP и User-Agent, auth methods/strength/time, last activity, expiry и risk state.
- Изменение IP или User-Agent переводит активную session в `elevated` и пишет `auth_event`; refresh replay переводит family/session в `compromised` и отзывает её.
- Пользователь может просматривать sessions, переименовывать устройство без изменения device ID, отзывать одну session, все остальные или выполнить logout-all. Admin API фильтрует sessions по user/provider/status/risk и умеет массово отзывать user/provider/risk выборку; provider-wide compromise требует свежую phishing-resistant authentication.
- Provider logout отделён от Never logout: поддерживающий revoke connector получает provider credential server-side, credential удаляется после revoke, но Never session остаётся активной до отдельного revoke/logout.

### Access-token key rotation

- Access token теперь compact JWS/JWT `HS256`, а не custom `base64(payload).HMAC`. Header содержит `typ=JWT`, `alg=HS256`, `kid`; verifier проверяет issuer, audience, token use, timestamps, session id и key id.
- `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON` задаёт keyring `kid -> secret`, `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID` выбирает signing key. Предыдущий key остаётся verify-only до истечения выпущенных им access tokens, после чего его можно удалить. Старые production-конфиги с одним `AUTH_TOKEN_SECRET` продолжают работать через `primary` key.

## 0.11.7 — Passkeys / WebAuthn + MFA 2.0

`0.11.7` добавляет production WebAuthn/passkeys поверх существующего Federation Core. Passkeys являются реальным authentication method: credentials и одноразовые challenges сохраняются в PostgreSQL, assertion проверяет RP ID/origin/challenge/signature/user verification/sign counter, а password/SQL/HTTP/OIDC/Microsoft login проходит единый MFA policy до выпуска Never session.

### WebAuthn / Passkeys

- Discoverable credentials с `residentKey=required` и `userVerification=required`; поддерживаются ES256, Ed25519 и RS256 COSE keys.
- Registration принимает только `attestation=none`, проверяет RP ID hash, UP/UV, AAGUID, credential ID и COSE public key.
- Passwordless login и passkey continuation для password/federated login используют одноразовые PostgreSQL-backed challenges с TTL 5 минут.
- Session metadata содержит `authMethods`, `authStrength` (`single-factor`/`mfa`/`phishing-resistant`) и `authTime`; refresh сохраняет эту силу, а step-up выпускает новый access token.
- Passkey credential lifecycle: list/rename/revoke, backup flags, transports, `lastUsedAt`, sign counter и recovery-code cleanup при отзыве последнего credential.

### MFA 2.0 / Step-up

- Per-user policy: `optional`, `required`, `phishing-resistant`. TOTP и recovery codes остаются рабочими; passkey может удовлетворить MFA и обязателен для phishing-resistant policy.
- Критические операции используют fresh authentication: release publish/rollback и migrations требуют свежую MFA; package signing, backup restore, user role changes и ServerBridge token rotation требуют свежую phishing-resistant authentication.
- WebAuthn RP ID/origins валидируются fail-closed в production; sensitive passkey/OIDC/Microsoft auth routes используют auth rate-limit bucket.


## 0.11.6 — Microsoft Connector

`0.11.6` добавляет production Microsoft identity connector как специализацию рабочего OIDC Connector/Federation Core, а не отдельный OAuth engine. Поддерживаются Microsoft identity platform v2 Authorization Code + PKCE S256, `common`/`organizations`/`consumers` и single-tenant GUID authorities, global/US Gov/China clouds, tenant-independent issuer validation, JWKS signing-key issuer validation и стабильная canonical identity на основе `tid + oid`. Microsoft login не считается доказательством владения Minecraft.

### Microsoft identity runtime

- Microsoft provider регистрируется через `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` / `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE` и проходит discovery/JWKS/health/conformance до открытия API трафику.
- `offline_access` добавляется обязательно для server-side refresh credential lifecycle; app secret берётся только из environment/file.
- Multitenant token проверяется одновременно по `tid`, фактическому tenant-specific `iss` и `issuer` конкретного JWKS signing key; `allowedTenantIds` может дополнительно сузить trusted tenants.
- Stable external subject — `tid:oid`; mutable email/UPN/name используются только как profile attributes и не участвуют в identity ownership.
- Microsoft external groups/roles не становятся Never roles напрямую: повышение возможно только через локальный `roleMappings` policy при JIT provisioning.

### Account linking / provider credentials

- `explicit-only` остаётся default. Authenticated Never user может выполнить `POST /api/v1/auth/microsoft/{providerId}/link/begin` → provider proof → `.../link/complete`; совпадение email не используется для auto-linking.
- Microsoft/OIDC refresh tokens сохраняются только server-side в `provider_credentials` как AES-GCM envelope, привязанный AAD к user/identity/provider/subject. Plaintext provider token не возвращается клиенту и не становится Never access/refresh token.
- `POST /api/v1/auth/providers/{providerId}/credential/refresh` выполняет provider rotation через Connector SDK и fail-closed проверяет неизменность subject. `DELETE .../credential` удаляет локально сохранённый provider credential.
- `POST /api/v1/auth/microsoft/{providerId}/logout-url` строит allowlisted Microsoft front-channel logout URL отдельно от Never logout/session revoke.

### Scope boundary

Microsoft identity и Minecraft ownership/profile намеренно разделены. `0.11.6` не интерпретирует успешный Microsoft sign-in как Minecraft entitlement и не запрашивает Xbox/Minecraft ownership APIs; это остаётся отдельным entitlement/profile verification layer последующих compatibility работ.

## 0.11.5 — OIDC Connector

`0.11.5` добавляет production OIDC federation поверх Connector SDK/Federation Core: OpenID Provider Discovery, Authorization Code + PKCE S256, state/nonce, JWKS key rotation, ID Token signature/issuer/audience/azp/time validation, optional UserInfo merge с обязательным совпадением `sub`, configurable claims mapping, explicit-only/JIT provisioning и browser/desktop begin/complete flow. OIDC transaction stateless и AEAD-защищён, поэтому не требует process-local session map. Provider tokens не используются как Never tokens.

## 0.11.4 — HTTP Connector

`0.11.4` добавляет второй внешний production auth provider поверх Connector SDK/Federation Core: hardened HTTP Connector для существующих CMS/API. `/api/v1/auth/login` и `/api/v1/admin/login` реально маршрутизируют password authentication в удалённый provider по `providerId`; успешный external subject затем проходит обычный canonical identity/JIT flow и получает Never session, а provider token не становится Never token.

### Remote authentication protocol

- Реальные `POST /authenticate`, `POST /refresh`, `POST /resolve`, `POST /logout` и `GET /health`; paths могут быть переопределены только в startup config и всегда остаются относительными к одному `baseUrl`.
- Strict protocol envelope `neverlauncher-http-auth/1`, обязательный `issuer`, стабильный `subject`, bounded identity fields/groups/roles/claims и fail-closed schema decoding.
- `/resolve` обязан вернуть тот же subject, который был запрошен; изменение subject считается provider misconfiguration.
- Remote error statuses преобразуются в typed Connector SDK errors без утечки произвольного текста upstream пользователю.
- HTTP provider поддерживает SDK password auth, user lookup, token refresh и token revoke; conformance проверяет заявленные capabilities при startup.

### Transport security / SSRF protection

- Только HTTPS; redirects и proxy environment отключены. TLS verification обязательна, поддерживаются custom CA и optional mutual TLS client certificate.
- `hostAllowlist` применяется к каждому dial. Connector выполняет DNS resolution сам, валидирует все полученные IP и соединяется непосредственно с уже проверенным IP, сохраняя TLS hostname verification.
- Loopback, private, link-local, shared, multicast, reserved и documentation networks заблокированы по умолчанию; private endpoint требует явного минимального `allowedCidrs`.
- Connect/request/response-header timeout, bounded connection pool, idle timeout и response size limit конфигурируются с безопасными пределами.

### Request/response authenticity

- Каждый request подписывается HMAC-SHA256 по method/path/timestamp/nonce/body SHA-256; secret берётся только из environment variable или secret file, не из provider JSON.
- Каждый response, включая error response, обязан вернуть тот же nonce и valid HMAC над status/timestamp/nonce/body. Используются constant-time comparison, timestamp replay window и consumed-nonce cache.
- Неподписанный, просроченный, повторный или подписанный другим key response отклоняется до разбора identity.

### Federation / production integration

- `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON` / `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE` подключены к реальному startup registry рядом с SQL providers; unreachable/misconfigured provider останавливает startup fail-closed.
- `jit` и `explicit-only` используют тот же Federation Core policy: JIT создаёт canonical Never user + `auth_identity`, но не fake local password; совпадение email не даёт implicit linking.
- Production Compose/CLI templates передают HTTP provider config и отдельный HMAC secret environment variable.
- Integration test поднимает настоящий TLS auth service, проверяет HMAC request/response flow и выполняет HTTP provider authentication через `NewFederationCore114` до persistent canonical identity.

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

## [0.35.13] — Owner Lifecycle Readback, Durable Operation Recovery and G/M Regression Continuity

- Completed the Admin owner path around existing real Build Workspace, validation, signed package publication, durable jobs, channel-head observation, rollback and operator diagnostics. The same backend operations remain authoritative; HTTP 202 never means `published`.
- Publish/rollback now bind an explicit preview to the project/profile/channel and pre-operation channel-head revision. They persist an exact idempotency intent before network I/O. On lost acknowledgement, the owner can replay *only* the saved request/key, not accidentally create a second rollback. Project/account-scoped saved intent contains no credentials.
- Job observation cross-checks project/kind/resource with the live Backend, then verifies `succeeded` against the real channel head; rollback also checks that the newly published release matches the durable job's `result.packageId`. A stable rollback staged pending trusted runtime validation is clearly distinguished from a published rollback.
- Legacy direct Admin publish button redirects to Release Workspace. The owner can view current channel-head state, navigate to job/audit/ServerBridge/diagnostics and explicitly resolve a stored operation.
- Repaired the 0.35.1 G01–G35/M01–M19 acceptance runner's hardcoded `VERSION=0.35.1` check: historic catalog and `not-run` target evidence remain immutable, while local regressions run against later source versions. No unexecuted G/M or full owner/real Minecraft E2E is marked verified.
- Added negative/execution tests, targeted native Backend regression workflow and a disposable authenticated owner/player HTTP journey in CI. Local Admin unit tests and G/M inventory passed; full React build, Go 1.27.3, real deployment and Minecraft/ServerBridge attestation must still run externally.

## [0.35.12] — Isolated Chaos, Full-State Snapshot and Fresh-Site DR

- Added a runnable Docker Compose DR tool: quiesced PostgreSQL custom dump, filesystem/factory/coordinator/backups volumes and optional Redis AOF state, plus a separately provisioned S3 mirror with object hashes.
- Added fail-closed SHA-256 archive verification, traversal-safe tar checks, restore only to a new empty project, with separately approved production maintenance/fresh-site options, PostgreSQL transactional restore, S3 empty-target enforcement and readback of every restored object.
- Added real component fault-injection actions for PostgreSQL, Redis (network-ha), and API process, measuring `/ready` failure/recovery times.
- Hardened Go backup extraction against oversized decompression and S3 restore against silent object corruption.
- Added negative security tests, CI compilation/test workflow and documented exact execution/DR evidence boundaries. Local Docker/Go 1.27.3/S3 platform results remain unverified, so no HA/RPO/RTO or full disaster-recovery certification is claimed.

## [0.35.11] — Measured Runtime, Desktop Startup, CPU/RAM and Backend Latency

- Added a real process benchmark harness invoking compiled NeverRuntime against a locally signed certification manifest, including 10,000 physical files with native SHA-256 verification and measured CPU/RAM usage.
- Implemented bounded-memory HTTP Range server for native download and warm-update measurements at 1/10 GiB, with independent file hashing and actual wire-byte accounting; large tests require explicit consent and sufficient disk space.
- Added native Tauri timestamp marker for first React paint after two animation frames, allowing first-process and subsequent-process start measurements without modifying privileged Desktop capabilities or enabling telemetry for players.
- Added read-only bounded-concurrency HTTP latency measurements with p50/p95/p99 and optional live Backend process sampling; reports retain executable hashes and stand metadata, do not invent baseline comparisons.
- Added cross-platform native smoke workflow and Linux Desktop startup workflow. Full large-network workload, full native compile and real packaged Desktop/Backend latency measurement must be executed on suitable test hardware before production performance claims.

## [0.35.10] — Player & Operator Diagnostics, Explicit Consent, Support Inbox

- Replaced unsafe substring-based diagnostics export with a native one-time reviewed report. No raw player logs, URLs, paths or credentials are retained; only bounded, allowlisted event category counts and platform/status metadata are included.
- Export is native, atomic and private in the app-owned config directory. Previewed payload is preserved unchanged, bound to an expiring one-time review token and never accepts a renderer-selected export path.
- Player may manually save or, after authenticated explicit consent, submit a report to Backend. Support ingestion rejects free-form fields and unknown event categories, bounds payload size and stores under a private operator directory.
- Admin Diagnostics has an operator export, support inbox, detail view and local download; access requires `diagnostics:read`.
- Operator diagnostics exclude local paths, infrastructure URLs, database DSNs and raw health exception messages.
- Rust/Go/Node negative tests and CI workflow added. Full native/Backend E2E certification not claimed without platform toolchains and live tests.

## [0.35.9] — Desktop Settings Migration, Signed Preset Requirements and Player File Preservation

- Native Desktop config schema `1.0 → 1.1` migration, exact legacy backup, retained unknown user preferences, fail-closed future versions.
- Real installed-vs-new signed release requirements comparison (Java, RAM, Minecraft/loader, component selection); explicit signature-scoped acceptance.
- Explicit preservation of conflicting untracked player files in a durable indexed archive before managed release installation; no implicit overwrites.
- New UI in Downloads, first-run and optional components; native negative tests and cross-platform CI checks.
- Source-level release only; Rust/Tauri and Minecraft platform certification pending.

## [0.35.8] — Owner-Authorized Offline Playback & Verified Cache

- Native Desktop enforces signed owner bootstrap, exact project/profile/channel, pinned Ed25519 key, completed first-run digest and saved canonical installation directory before allowing offline cache replay or game launch.
- Offline cache is updated **only after successful installed release/preset and managed file SHA-256 verification**, including first-run install, component selection, repair and durable resume. Merely fetching a newer signed manifest cannot evict a still-active cached release.
- Real `prepare_offline_launch_0358` command verifies the installed transactional release and component preset without contacting Backend or creating credentials; native `launch_minecraft` independently rechecks identity/cache, and NeverRuntime checks files again under a launch lease.
- Renderer switches to offline only on native success, never retains signed online auto-enter/ServerBridge selection for offline, and displays specific recovery actions. Offline has no Microsoft entitlement, token or ServerBridge ticket; runtime rejects signed game arguments that try to auto-join a server.
- New Desktop regression tests and negative native Rust tests, plus a 3-platform CI build/test workflow. Local native compilation, packaged Tauri and live Minecraft/ServerBridge offline E2E remain unverified.

## [0.35.6] — CSP, Sandbox, Native Bridge Revocation & Hardening

- Desktop extension UI now rejects stale or malformed catalog/HTML/RPC payloads, mismatched scopes, untrusted message origins, duplicate in-flight requests and cross-generation responses.
- Existing Backend RPC rechecks live `desktop:bridge` grants, verified device session, extension version and install generation before any extension-initiated native call; revocation denies new calls.
- Main Tauri local-only capability restricts core API to event listening; production and dev CSP separated, main JS stays `script-src 'self'`, prototype freezing enabled.
- Extension CSP injected ahead of all third-party markup. External branding/Microsoft URLs open via restricted native HTTPS system-browser command. Native game-folder opener is limited to the saved canonical root.
- Node/Go/Rust regression tests and CI added. Native/Backend compilation and real sandbox UI E2E remain unverified locally; inherited `srcDoc` CSP is a known blocker for inline extension scripts and cannot be treated as a complete interactive plugin GA.

## [0.35.3] — Player Workspace & Finished Desktop Navigation

- Replaced technical sidebar with player-oriented Accounts, Servers, Builds, Optional Mods, Textures, Downloads and Launch History; signed first-run and diagnostics remain accessible where appropriate.
- Production build selection now fetches Backend project/profile catalogs, verifies owner-pinned Ed25519 manifests with native NeverRuntime, isolates game directories via native prepare_profile_directory and commits selections via native save_desktop_config before displaying a verified active build.
- Active profile ServerBridge browser, explicit persisted server selection, unsigned/signed binding constraints, and clear separation between node IDs and public Minecraft addresses.
- Working optional mod chooser/portability and existing skin/cape UX moved to direct navigation; structured native launch history with status filters, details and stop action.
- Screen restore only after native Desktop config/signature verification; pre-verification authentication requests and navigation blocked; offline/ServerBridge restrictions preserved.
- Added 0.35.3 workspace interaction tests, existing regression coverage and a CI job that performs the actual React production compile. Local full TSX/Tauri build remains unverified when npm dependency cache is incomplete.

## [0.35.2] — Owner-signed first-run Desktop

- Prestarter now hands off the exact verified signed bootstrap envelope (and verified v2 policy) to native Desktop, without trusting unsigned local preferences for backend/project/profile/channel/public key.
- Desktop independently verifies the signed owner provisioning using a compile-time Ed25519 root; fail-closed when a signed bundle has no embedded trusted root or fails verification.
- Integrated account → verified project/profile → runtime/Java → optional preset/server → transactional download → native post-install verification → Play first run.
- Native completion cannot be asserted by JavaScript preferences; optional signed server auto-enter configuration is supported.
- Preserved desktop user preferences and advanced manual binding for non-bundled operator builds.

## 0.35.1 — G/M User Journeys & Executable Acceptance (UX12 baseline)

- New current G01–G35 and M01–M19 player/owner/operator journey inventory; real success/negative outcomes, operator steps, source and executable test references, preserved historical status, explicitly unverified target state. M17 remains a prohibited unsafe capability.
- Executable Python audit validates all 54 required IDs, source and probe paths, UX01–UX12 mappings and rejects unsupported completion claims. Local runner executes existing Node/Go test packages without shell injection, writes atomic redacted result receipts and never upgrades local passes to GUI/GA certification.
- Disposable, real Backend owner/player acceptance runs authenticated project/profile/channel CRUD, player catalog readback, unpublished file denial, audit access control and refresh/logout revocation; safe loopback-only and explicit ephemeral-server acknowledgment.
- Dedicated CI for inventory, Desktop regression/optional components and real Backend lifecycle, plus reproducible runbook and honest local evidence report. No real Minecraft/ServerBridge/GA acceptance claimed. 0.35.0 stable release guard unchanged.

## 0.34.11 — Production Release Gate (V11)

- API re-verifies each mandatory signed v4 ValidationEvidence against the staged snapshot, positive stages, persisted execution, pinned runner/Java/preset/Guard/adapter/server identity, trusted signature, challenge, expiry and key revocation. Missing, failed and inconclusive targets block stable.
- Durable publish obtains a fresh one-use permit only after complete target coverage. PostgreSQL release-status/head triggers re-check backed attestation rows and integrity inside the commit, consuming the permit atomically. Manual certification flags and direct head/status writes are rejected.
- Migration Center cutover/rollback require the same gate; rollback-as-new-release remains staged pending new validation. Dev/test policies remain independent. Admin UI reports policy fingerprint, coverage and target blockers.
- PostgreSQL migration `0105` enforces the guard and append-only evidence. Full Go/PostgreSQL and real staged Minecraft E2E deployment verification remains mandatory; not performed in this environment.

## 0.34.10 — Cross-Platform Runtime Runners (V10)

- Observed capability registry for Windows, Linux and macOS (amd64/arm64): actual Java binary/version, display availability, usable OpenGL context/renderer. Missing GUI/renderer is BLOCKED, never Minecraft FAILED.
- Native Windows/macOS game-window PID/process-tree verification, screen capture, visible menu OCR and real keyboard gameplay input; Linux/X11 retains existing verified path. Missing Screen Recording/Accessibility grants prevents positive validation.
- Headless staged runner downloads and installs signed bytes through the normal CLI but explicitly blocks startup/gameplay and cannot sign a complete runtime target. Independent attestor verifies GUI capability evidence before Ed25519 signing.
- Per-job temporary directories, portable process-tree termination (including interrupted updater), bounded execution, redacted observational exports, and opt-in self-hosted Windows/Linux/macOS native CI.
- Stable remains blocked; native self-hosted runners must actually execute full Minecraft/Java/ServerBridge matrix to establish platform compatibility. Cross-platform observational CI output cannot substitute for independent attestation.

## 0.34.9 — Update, Recovery & Rollback (V09)

- The staged Minecraft E2E now runs the production transactional CLI against a **host-pinned previous signed release**, then upgrades to the exact staged package, corrupts installed files and preferred cache, executes repair, and rolls back via the actual snapshot. Both the updated client on alternate Java and restored previous client must reach a positively verified Minecraft menu.
- Fault injection terminates the actual updater process during observed `staging` and `committing` journal phases and uses public `update recover` to restore the exact prior bytes before retry. HTTP interruption tests use the real staged downloader and compare retried byte hashes. Missing observations never become PASS.
- Separate `update-recovery` stage, on-disk diagnostics, independent host-side verification, mandatory Backend evidence, fail-closed prior-release/Java inputs, and executable real-CLI regression tests.
- Stable is still blocked. Full live Minecraft E2E, pinned Managed Java distribution-manager replacement execution and Backend Go 1.27.3 tests are not validated in the local build environment.

## 0.34.6 — Evidence Freshness & Invalidation (V05)

- One-time persistent attestation challenges, V3 domain-separated evidence, purpose/audience/nonce/freshness validation.
- Operator-pinned required target policy for exact Java, preset, adapter, Guard, source/build and matching server identity; all targets share one immutable staged snapshot.
- Durable emergency signing-key revocation, live applicability reporting and signature re-verification. Stable publishing remains deliberately blocked until V11.

## 0.34.5 — Signed ValidationEvidence & Runner Trust (V04/V06)

- Host-side independent Ed25519 attestor executes an immutable, operator-pinned OCI image via rootless Podman, using only a short-lived staged grant; release-signing and attestation keys remain separate.
- Exact staged downloads, client installation, menu/loader, matching server and gameplay output are independently re-hashed and checked by the host before attestation signing. No CI-generated arbitrary JSON can be signed by the service.
- Backend verifies the domain-separated signature, trusted attestor public key and pinned runner-image SHA-256, matches immutable staged manifest, current integrity proof and recorded per-stage digests, then persists one immutable evidence record per run.
- No direct stable publish path is enabled; V05 applicability and complete production release certification remain pending.
- Production deployment requires a rootless attestor host, signed/pinned runner image, Java/ServerBridge targets, GUI renderer, network ACL and separate attestor key; no full real-world Minecraft E2E was run in the build environment.

## 0.34.2 — Real staged runtime execution (V01/V02)

- Time-limited, snapshot-bound runner grants and authenticated staged file delivery.
- Real byte-for-byte staged downloads, transactional client install, verification, NeverRuntime startup attempts.
- Durable per-stage observational reports (PostgreSQL and memory), with no stable certification bypass.
- Staged storage no longer accessible via anonymous public file route.

## [0.34.1] - 2026-10-28

### Stable Release Protection — V11, first phase

- The API refuses all new stable publication, regardless of project `requiredLevel=integrity`, missing policy or legacy `neverlauncher/runtime-validation/v1` JSON signed by a configured key. Legacy v1 is *not* trusted independent client/server execution.
- Durable publish workers recheck the gate; rejected attempts persist a structured `release:publish-blocked` audit event with reason code `stable_runtime_certification_unavailable_0341` and job rejection details. Rollback is staged without stable activation, with the blocking reason.
- PostgreSQL migration `0101_stable_runtime_gate_0341` rejects new stable `published` status and **all** stable `channel_heads` writes, including direct repository writes, migration cutover, rollback and arbitrary SQL edits. Existing stable heads continue to serve existing releases. API and CLI embed the guard.
- Dev/test keep their configured project-level `integrity` or `runtime` policy independently of the hard stable gate. Admin displays effective stable policy and prevents unfulfillable stable actions in the UI.
- Stable remains closed in 0.34.1: future V01–V12 must introduce independently attested package-specific execution before it can reopen. This release does not claim game client/server certification.

## [0.34.0] - 2026-10-28

### Migration Center GA verification and release gates (MIG01–MIG13)

- Shipped a standalone, executable GA acceptance tool (`tools/migration-ga`) that retrieves the authoritative MIG13 report and immutable operator review, recomputes its SHA-256, checks identity resolution and active Never cutover, and binds the exact MIG03 source ZIP and independently SHA-256-pinned Gravit 5.7.x LaunchServer JAR binary and version to the active signed release digest.
- The tool runs all 13 mandatory independent acceptance checks as real subprocesses with timeouts, bounded output, fresh hash-verified evidence, complete UUID parity and world/plugin checks. Failure, missing evidence, changed backend report or missing review emits no GA success bundle.
- On complete success, generates an Ed25519-signed, replay-resistant, owner-only evidence certificate with a separately trusted offline verification command. It cannot silently overwrite an existing certificate. The checks and their underlying evidence must still be independently audited.
- Hardened MIG13 reporting: a manually staged/cancelled cutover, unresolved required stages or an unrecognized evidence status now block RC readiness instead of being treated as verified.
- Added full GA CI with Backend/PostgreSQL, Admin, Desktop Rust builds across Linux/Windows/macOS, executable verifier tests and an explicitly required independent isolated Gravit/Minecraft E2E runner. Version and OpenAPI metadata aligned to 0.34.0.
- **GA certification is conditional on successful actual CI and real, isolated Gravit/Minecraft E2E with external source writer fencing. Those tests have not been executed in this offline build environment. No production compatibility or safe cutover claim is made solely by the version bump or by simulated unit tests.**

## [0.33.13] - 2026-10-28

### Reports & Certification RC (MIG13)

- Real PostgreSQL-backed report from MIG02–MIG12 receipts, current UUID mapping, Build Workspace and channel heads. Deterministic SHA-256, per-object transferred/transformed/manual/blocked classification, missing-evidence blockers and sanitized operator audit sequence.
- Read-only repeatable-read report generation, verified canonical digest, immutable SHA-256-pinned MFA operator review with serializable race checks and idempotent retry. RC review never implies GA certification or grants cutover.
- `nl migrate gravit report|report-review|report-review-status`, React Admin and Embedded Admin UI, PostgreSQL migration 0100, OpenAPI (430 operations), race/DB/CLI tests, CI and runbook.
- **Limit:** real isolated Minecraft Gravit migration E2E, externally verified source fencing, independently signed installer evidence and full GA certification remain pending and are not fabricated by CI or operator-supplied digest fields.

## [0.33.12] - 2026-10-28

### Operational Rollback (MIG12)

- Safe, transactional rollback of the real Never `channel_heads` release pointer (and delete when the channel did not exist before cutover), with old Never Ed25519 signer verification, CAS, journal, saved immutable plan and idempotent replay.
- MIG11 channel writer guard now blocks ordinary INSERT/UPDATE/DELETE while cutover is staged **or active**. Atomic rollback retains the original activation metadata and a completed receipt.
- Strict re-evaluation of live production world/UUID/inventory/permissions/economy/skin/loader/optional snapshots against MIG10; post-switch changes require an independently merged Gravit snapshot with complete semantic parity, or rollback is blocked. A fresh second snapshot and both writers' independent fencing acknowledgements are required before commit.
- CLI `rollback-plan`, `rollback-commit`, `rollback-status`, MFA Admin and Embedded Admin; PostgreSQL migration `0099`, integration tests, dedicated CI and operations runbook.
- **Explicit limit:** no automatic backup restoration, world/SQL data merge, remote Gravit stop/resume or provable external fencing. Unreconciled post-cutover changes require external/manual reconciliation. Full backend/PostgreSQL/game E2E certification remains separate.

## [0.33.11] - 2026-10-28

### Staged Cutover (MIG11)

- Transactional, per-project/profile/channel Never release switch through the real `channel_heads` delivery pointer, not a simulated traffic flag. PostgreSQL migration 0098 fences ordinary writes to staged scopes using a trigger and requires a matching run-scoped transaction for the activation CAS.
- Requires a fresh successful MIG10 rehearsal, UUID checks, MIG05/MIG06/MIG08 receipts, exact MIG07 release ownership, current Never Ed25519 signer verification, fresh source snapshot digest and source-writer fencing evidence reference. Activation, revision and event journal commit atomically. Replays are idempotent.
- CLI and React Admin support stage, activate, cancel-before-activation and audit/readback; project-level authorization and fresh MFA are enforced by Backend. Includes PostgreSQL integration/race tests, dedicated CI and operations runbook.
- **Operational limit:** Never cannot itself stop or prove the Gravit server/database/world writers are fenced. The operator must do so independently; source fencing and source snapshot hashes are supplied as attestation, not remotely verified. MIG12 must implement reconciliation before any post-cutover rollback. Production certification and real source writer HA cutover are not claimed.

## [0.33.10] - 2026-10-28

### Isolated Migration Rehearsal (MIG10)

- CLI executes seven real, operator-provisioned stage-side probe binaries without a shell, with bounded runtime/stdout, minimal environment and on-disk evidence hashing. Refuses missing tests and staging paths escaping the operator-declared sandbox.
- Source and post-test target snapshots compare Minecraft UUIDs, world checksums, inventory, plugin permissions, economy, skins, loader, optional presets and administrator roles.
- Server independently recomputes results, binds player identities to MIG04 and prerequisites to MIG03/MIG05/MIG06/MIG07/MIG08; migrated workspaces must have complete staged file paths and checksums.
- PostgreSQL migration 0097 stores immutable stage-specific reports with event journaling, safe retry and history across distinct rehearsal stage IDs. CLI, React Admin and Embedded Admin expose actual status. Cutover is **always forbidden** by MIG10.
- Unit/race tests, CLI process execution tests, PostgreSQL integration test and CI workflow. The operator MUST provision a physically/network isolated test environment and real Minecraft/plugin test binaries; CLI cannot prove that an operator-declared stage is isolated, and probe results are not cryptographic attestation of gameplay. This does not implement staged cutover or rollback.

## [0.33.9] - 2026-10-28

### Player Migration Assistant (MIG09)

- Desktop UI to choose a previous Gravit/Minecraft directory, preview verified reusable files and explicitly approve adoption; common legacy locations are suggested without automatic copying.
- Only bytes whose size and SHA-256 match the independently Ed25519-signed Never release manifest are published to NeverRuntime's existing shared content cache. Existing OS-wide per-object locks, rehash on publication and ordinary signed release installation are reused. No direct modification of the game tree.
- Candidate optional components are reported from signed file content, never automatically enabled. Minecraft display preferences can be applied only with explicit consent; no tokens, keys, passwords, JAR execution or old trust anchors are imported.
- Rust tests, Tauri commands, UI panel, CI workflow and player runbook. Independent installer distribution signatures and end-to-end clean installs still require release validation.

## [0.33.8] - 2026-10-27

### Module & ServerWrapper Migration (MIG08)

- Static, bounded JAR inspection from a MIG03 hash-pinned Gravit source ZIP; no JAR execution.
- Unknown executable JARs (including auth/launch hooks) are explicit blockers, not falsely compatible adapters.
- ServerWrapper JSON and inline environment recognition; sanitized reports never include legacy secrets.
- Immutable module review in PostgreSQL, audit trail and replay-safe receipt.
- Fresh Ed25519 Never ServerBridge registration of reviewed ServerWrapper nodes with MFA, new key, exact run confirmation and durable binding receipt. Fresh signed heartbeat and login/join tests remain required.
- CLI and Admin controls, race-test fixtures and CI for MIG08.

## [0.33.7] - 2026-10-27

### Content & Profile Migration (MIG07)
- Verified MIG03-source ZIP ingestion for supported ClientProfile, one client tree, libraries and assets. Profile and owned Build Workspace are reserved in a single PostgreSQL transaction with deterministic idempotent identity; encrypted bytes are staged into the real Build Workspace and individually rehashed on retry.
- OptionalFile actions are converted by the existing strict parser; unsupported behavior, missing libraries and collisions block import. Converted component catalog can be applied only to a file-matched unsigned v3 draft.
- Package signer rejects mutated migrated bytes, ownership changes and missing/mismatched optional catalogs. Never's existing high-assurance validation/Ed25519 signing and publication remain separate required operator operations.
- CLI, React Admin and Embedded Admin, PostgreSQL migration 0095, Go unit/race + PostgreSQL integration tests, CI and runbook. TextureProvider is handled by the existing separate offline verified importer.
### Limitations
- No unknown Gravit bootstrap/modules, automatic cutover or rollback. Source ZIP must use the supported per-profile path layout; individual workspace files limited to 64 MiB. Full Go 1.27.3, PostgreSQL and React builds are mandatory CI release gates, not locally certified here.

## [0.33.6] - 2026-10-27

### Security & Trust Migration (MIG06)
- PostgreSQL transactional security reset for MIG05-imported users with target UUID verification and durable per-run receipt; preview rolls back, replay never re-revokes newly enrolled Never devices.
- Revokes active sessions through the existing PostgreSQL cascade (refresh families, Minecraft sessions, joins and ServerBridge tickets), device trust/attestation, outstanding enrollment challenges, TPM and measured-boot evidence. Existing Never accounts matched by MIG04 are not modified.
- Rejects default/development signers during reset: explicit Never JWT key set and configured Ed25519 manifest signing seed are mandatory. Operator must acknowledge independent provisioning; never imports Gravit private keys or trust anchors.
- New CLI/Admin operations for preview, explicit apply and durable verification, plus 0600 exclusive local key generation; integration and unit tests. This **does not** perform production cutover or certify independently provisioned infrastructure keys.

## [0.33.5] - 2026-10-27
### Added
- MIG05 executable transactional PostgreSQL account import from immutable MIG03/MIG04 Gravit ZIP snapshots; preserves supported FileAuthSystem and normalized SQL password verifiers and Minecraft UUIDs.
- Per-account manual reset classification for unsupported SQL verifiers, safe dry-run, explicit import confirmation, durable idempotent receipt/retry, no credential overwrites for matched Never identities.
- CLI, React Admin and Embedded Admin operations, sanitized OpenAPI contract, integration/race tests, 0093 database migration and operational runbook.
### Limitations
- Existing Never passwords and official/remote providers are never silently replaced. No sessions, administrator rights, old signing keys, unknown JAR execution, cutover or rollback are migrated in this release.
- Full Backend Go 1.27.3/PostgreSQL and Admin integration certification requires the configured CI workflow; do not treat this implementation as a certified production release until those checks pass.

## [0.33.4] - 2026-10-27
### Added
- MIG04 executable identity mapping for real Gravit FileAuthSystem `Database.json` (UUID-keyed records) and normalized SQL CSV `sql-export/users.csv` (id,username,uuid).
- Immutable source-scoped identity snapshots with SHA-256 provenance pinned to MIG03 inventory, PostgreSQL target reconciliation, UUID/name/provider ID collision detection, and transactional event journaling.
- Authenticated Admin, Embedded Admin and CLI identity scan, display and live re-verification. Credentials, tokens, external trust and passwords are not imported.
### Limitations
- A source UUID without an existing matching Never identity remains `pending_import` for later authentication migration; same-name matching never proves account ownership.
- No account auto-creation, manual override, world/plugin-data reassignment, player session migration or cutover is performed in MIG04. `ready` refers only to the identity mapping, not project migration readiness.
- Complete Go 1.27.3/PostgreSQL/React production integration verification requires an environment with those toolchains/services.

## [0.33.3] - 2026-10-27
### Added
- MIG03 operational source inventory of a real bounded Gravit ZIP: streaming CRC/SHA-256 validation of every file; detailed classes for clients, assets, libraries, profiles, modules, textures, auth providers, optionals, server references and keys; malicious path/duplicate/ZIP bomb rejection.
- Transactional, idempotent, sanitized PostgreSQL inventory snapshots tied to durable runs and pinned against compatibility source digest, with append-only event journal.
- Fully reproducible verified ZIP export containing actual original source bytes plus canonical checksum manifest. Source ZIPs are only spooled temporarily with mode 0600; secrets never enter inventory SQL. CLI verifies downloaded archive contents before publication and refuses overwrites.
- Admin SPA, Embedded Admin, CLI `inventory|export`, PostgreSQL migration 0091, native unit/race/SQL/CLI tests, version 0.33.3 and OpenAPI integration.
### Limitations
- Gravit Compatibility Detector 0.33.2 still accepts 64 MiB ZIPs, whereas the independent 0.33.3 inventory/export path accepts up to 512 MiB compressed / 2 GiB expanded / 30000 entries. Projects over the limit are not supported yet.
- The exported ZIP may contain credentials and is not encrypted or independently signed. Store it securely. No import, player identity reconciliation, module execution or cutover is implemented by MIG03.
- Full Go 1.27.3 Backend + live PostgreSQL and React production-build certification requires CI execution; not claimed locally.

## [0.33.2] - 2026-10-27
### Added
- MIG02 operational Gravit compatibility detector: bounded, non-executing analysis of Gravit source ZIP (LaunchServer, runtime, ClientProfile, optional actions, modules, ServerWrapper config/env), with detailed recognized/manual/blocked findings.
- Conservative version recognition for Gravit 5.7.0–5.7.12: differentiates untrusted operator claims from an embedded LaunchServer JAR manifest, blocks conflicts and out-of-range versions; does **not** assert official provenance or full migratability.
- Transactional PostgreSQL report persistence tied to MIG01 prepared runs; same-source replay is idempotent, alternate source creates an auditable revision, secrets are never stored.
- Authenticated Admin SPA and Embedded Admin ZIP upload, `nl migrate gravit assess|compatibility`, OpenAPI contract and native-detector/CLI/PostgreSQL CI tests.
### Safety and remaining work
- A compatibility report is assessment only; it never authorizes import, account transfer, identity reconciliation, production cutover or rollback. Unknown auth and optional action types block assessment. No Gravit code or JAR is executed.
- Production GA requires pinned real upstream 5.7.x fixtures, integrated authentication and world-data rehearsal, and successful Go 1.27.3 + PostgreSQL CI; not claimed by this milestone.

## [0.33.1] - 2026-10-27
### Added
- MIG01 durable PostgreSQL migration run engine: atomic claims, leases, fencing, transaction-bound checkpoints, append-only events, idempotent run creation, pause/resume and failure recovery.
- Authenticated Admin routes, embedded Admin controls and `nl migrate gravit` CLI for running a real, read-only Never target baseline verification and inventory.
- Explicit fail-closed handling for unknown Gravit source adapters, import, cutover and rollback (planned for subsequent 0.33.x milestones). `prepared` is not a completed migration.

## [0.33.0] - 2026-10-27

### Added
- Fail-closed Single-Node GA release certification: independently signed Ed25519 live acceptance, pinned out-of-band public key, exact-commit 0.33.0 RC receipt, strict rejection of PostgreSQL/Redis masquerading as SQLite-only.
- Bound signed GA evidence to release BOM, signed manifest, build, sign, verify and publish-check; protected release workflow and production operating runbook.

### Not certified
- Full SQLite-only HTTP repository, independent installed GA evidence, multi-host HA and automatic SQLite-to-PostgreSQL production cutover remain unconfirmed. Release publishing is blocked without real GA evidence.

## [0.32.16] - 2026-10-27

### Production RC — fail-closed executable testing
- Bounded, concurrent, persistent SQLite coordinator load test verifies the exact authorization budget after restart.
- Fixes the capacity benchmark wrongly counting 401/403/redirects and mixed unsuccessful HTTP responses as healthy capacity.
- Adds a Go JSON event-validated RC gate covering security, join/replay, crash recovery, backup/restore, leases/fencing, PostgreSQL transfer, real PostgreSQL/Redis/S3, and HTTP tests. SKIP/missing/failed tests block evidence generation.
- Wires the live PostgreSQL/Redis/MinIO CI gate into the existing production-release workflow before artifact release.
- **Not GA:** entire installed-product E2E, multi-host HA failover and full Go 1.27.3 integration results remain unverified here; SQLite-only HTTP and live PostgreSQL cutover remain unsupported.

## [0.32.15] - 2026-10-27

### DEP10 — Capacity & Diagnostics
- Live 60-second HTTP request/5xx/429/latency metrics and in-flight requests, served by a bounded low-cardinality collector; direct `/metrics` scrapes perform no new PostgreSQL reads.
- Background 30-second capacity snapshots: host heap/goroutines, local storage volume, PostgreSQL server-wide connections, DB size, durable job lease age/backlog, outbox backlog and aggregate inventory counts.
- Runtime `diagnose capacity` and diagnostics-permission-gated `/api/v1/operations/capacity` with fail-closed monitoring errors, staleness detection and actionable scaling warnings.
- Opt-in, read-only `neverlauncher-capacity-bench`: capped concurrency/duration, explicit remote approval, measured throughput/p95/p99 and early stop on SLO failure.
- Race tests, negative cases, CI and runbook. Thresholds are operator alert conditions, **not** hardware throughput guarantees. Full API CI/production workload certification and Network/HA multi-host failover validation remain outstanding.

## [0.32.11] - 2026-10-27

### DEP07 — Verified SQLite → PostgreSQL staging transfer (not production cutover)
- Add executable `sqlite-to-postgres` CLI reading an existing verified v326 SQLite backup and a PostgreSQL DSN from an environment variable.
- Transactional import of every SQLite durable table into a separate immutable PostgreSQL schema, preserving IDs, exact nanosecond timestamps, revocations, Minecraft UUIDs, package blobs, audits, leases and fencing values.
- Isolated test restore plus SQLite Core invariant validation; PostgreSQL read-back verifies row counts, actual payload SHA-256, PK/uniqueness and foreign keys before committing.
- Atomic one-shot staging, no partial writes to existing PostgreSQL Backend tables, no overwrite of existing import; native PostgreSQL integration tests supplied for CI.
- **Not complete DEP07:** the PostgreSQL HTTP Repository is not yet compatible with imported SQLite security state. Backend cutover and production-ready migration remain blocked.

## [0.32.10] - 2026-10-27

### DEP06 — SQLite Online Backup, Restore & Pre-Upgrade Gate
- Online WAL-consistent `VACUUM INTO` snapshot on a separate read-only connection without taking the application's owner lock.
- Protected `0600` immutable backup, fsync, SHA-256 manifest, integrity and foreign-key verification; rejection of corrupt snapshots.
- Offline restore with owner lock, explicit replacement, refusal of WAL sidecars, atomic publication and retained rollback hardlink.
- `neverlauncher-sqlite backup`, `backup-verify`, `restore`, `pre-upgrade` (isolated restore and Core invariant verification).
- Mandatory verified snapshot before automatic SQLite Core schema migrations, regression tests and CI workflow.
- **Limitation:** Full live-driver integration tests and production certification are not confirmed in this environment; HTTP Repository remains PostgreSQL.

## 0.32.5 — DEP01/02 SQLite Durable Jobs, Leases & Outbox (2026-10-27)

## [0.32.9] - 2026-10-27

- Добавлен Go CLI для подписанных Ed25519 offline installer bundles: pack/verify/install с SHA-256, проверкой пути и атомарной публикацией без перезаписи.
- Добавлены безопасное создание конфигурации и first-owner bootstrap из защищённых файлов.
- В Backend встроена компактная Admin-страница (`/admin/`) для readiness, первого владельца, входа и первого проекта.
- Интеграция 0.32.9 не заменяет полную React Admin SPA и не открывает SQLite-only HTTP Backend.


## 0.32.8 — Deployment Modes (DEP05; 2026-10-27)

- Detect actual Standard vs Network/HA topology and report evidence without exposing secrets (`neverlauncher-api diagnose deployment`). No unsafe automatic downgrade to memory.
- Acquire an OS-level exclusive single-instance lock before PostgreSQL migrations or worker startup; anchor to shared local storage or explicitly configured persistent lock path, and retain until shutdown.
- Reject mismatched HA configuration and unsupported SQLite-only HTTP repository instead of advertising a production Single-node mode before remaining repository parity is integrated.
- Retain fail-closed production rate limits and health-enforced runtime coordinator selection.
- Add Linux cross-process locking / mode selection tests and a native build CI gate.


- Add atomic migration 324→325 and SQLite WAL-backed durable job queue with permanent actor/action/payload idempotency scopes, retriable attempts, persistent lease fencing and crash recovery.
- Add single-writer job claiming, lease renewal, terminal/dead-letter states and append-only attempt history; expired workers cannot acknowledge or mutate jobs under outdated lease tokens.
- Implement persistent scope leases whose fencing tokens increase across release/expiry/restart; `CommitFencedJob` transactionally checks job + scope epochs and commits trusted local data mutations, job success and outbox events together.
- Add idempotent, lease-fenced at-least-once outbox delivery with backoff, retry limit and durable dedup tombstones. Never claim exactly-once external side effects.
- Ship live SQLite CLI operations, native-driver CI, concurrency/restart/failure/fencing tests and operational documentation. HTTP backend remains on PostgreSQL pending remaining DEP01/DEP03 gates; no production certification without native driver and supported filesystem tests.

## 0.32.4 — DEP01/02 SQLite Replay & Join Tickets (2026-10-27)

- Add persisted, uniquely constrained signed-request replay nonce ledger on SQLite WAL; pin nonce checks to Ed25519 node trust anchors, identity epoch, signed payload digest and bounded timestamp skew.
- Implement 256-bit opaque one-use join tickets, checked against current NeverLauncher/Minecraft sessions, project scope, roles, access-token revocation and auth epoch; atomically replace older active tickets.
- Atomically commit signed nonce consumption, ticket redemption CAS and append-only audit in one `BEGIN IMMEDIATE` write. Expired, consumed, revoked and rotated-key tickets fail closed; old tokens cannot be resurrected by ordinary update or deletion.
- Add transactional node enrollment/key rotation/revocation, secure operational CLI commands and schema migration 323→324 while preserving existing MFA encryption format.
- Add restart/concurrency/replay/migration tests, SQLite native-runner CI and an operator runbook. Single-node HTTP/ServerBridge remains disabled pending trusted-device/Guard/coordination parity and real-driver certification.

## 0.32.3 — DEP01 SQLite Authentication & Revocation (2026-10-27)

- Implement real transactional SQLite local login, session access/refresh tokens, persistent replay detection and family compromise with cascading Minecraft token revocation.
- Add operator-key-encrypted TOTP MFA, step replay fences, one-use recovery codes, and immediate session revocation on MFA changes.
- Persist stable Minecraft identities, Minecraft sessions tied to Never auth epochs, explicit revocation and local CLI lifecycle.
- Add schema upgrade 322→323, security/restart/concurrency tests, native-filesystem CI and operator runbook.
- SQLite HTTP API/coordinator is **not** enabled; complete parity, live driver testing and CI certification are still pending.

## 0.32.2 — DEP01 SQLite Core Repository (2026-10-26)

- Implement actual SQLite transactional CRUD for projects, profiles with immutable history/revision CAS, channels, signed release drafts/publication with atomic channel-head CAS, users/normalized role assignments and append-only audit.
- Persist the eight platform roles with real foreign keys. Enforce last-active-owner, role-change `auth_epoch`, trusted Ed25519 signature verification, immutability and fail-closed repository integrity checks.
- Add `neverlauncher-sqlite core-init|core-status|core-put|core-get|core-draft|core-update-manifest|core-publish`, real-driver integration and restart/concurrency/security tests, runner job, and operator runbook.
- Do **not** switch the Backend to SQLite until the remaining mandatory state (sessions, joins, jobs, extensions, packages, coordinator) has parity; PostgreSQL remains the live API repository. Full Go 1.27.3 + modernc SQLite driver test run is required before production certification.

## 0.32.1 — DEP00 SQLite Driver & WAL (baseline; 2026-10-26)

- Added fail-closed `internal/sqlitedurable` SQLite 3.54.1 driver (`modernc.org/sqlite` v1.61.0) for real on-disk WAL transactions, one-writer / bounded-reader pools, `BEGIN IMMEDIATE`, rollback on error, and explicit uncertain-commit failures.
- Added Linux ext4/xfs/btrfs filesystem verification, symlink/permission/owner guards, durable file and directory fsync probe, and cross-process exclusive owner locking. Other filesystems/OSes are not certified and reject SQLite opening.
- Added a `neverlauncher-sqlite verify|probe --db <path>` operational binary; `probe` actually commits a record, closes the DB, reopens it, and checks durability.
- Added process/crash/rollback/concurrency/fail-closed tests and a DEP00 CI job; updated backend Go build toolchain to 1.27.3.
- SQLite is **NOT** yet an API repository or single-node installation mode: DEP01–DEP10 remain necessary. Production API stays on PostgreSQL until parity is verified.

## 0.31.9 — Linux Native Extension Sandbox (2026-10-26)

- Implement kernel-backed sandbox for signed `isolated` native Backend and CLI targets on supported Linux x86-64: user/mount/PID/network/IPC/UTS namespaces, `pivot_root`, recursive read-only bind mounts, private `/proc`, scratch tmpfs, locked securebits, no-new-privileges, capability drop and seccomp BPF.
- Create every isolated process directly in a delegated cgroup v2 using `CLONE_INTO_CGROUP`; enforce memory, swap, CPU, pids, lifetime and `cgroup.kill` for all descendants regardless of process group.
- Keep Host Protocol reachable through a private namespace-local loopback proxy over a Unix socketpair; seal startup configuration in `memfd`. Mark a process `isolated` only after sandbox setup returns READY; never downgrade to unsandboxed execution.
- Refuse root Backend service, missing controller delegation, non-x86-64 hosts, absent required kernel features, Java callback RPC, reverse native callbacks, shared mounts, outbound network and secrets until their isolation/broker support is implemented.
- Add strict policy tests, Linux sandbox kernel-acceptance test (requires a suitably delegated real host), CI and operator threat model. Full cross-service build and live cgroup/userns security acceptance are not certified in this release environment.

## 0.31.5 — Measured Boot & PCR Verification (2026-10-26)

- Implement independently verified TPM2_Quote (Windows PCP/TBS and Linux tpm2-tools) with a one-time, domain-separated nonce bound to user/device/session/epoch and an explicit operator-owned PCR policy ID+hash.
- Require an AK already verified through TPM2 Certify for the exact active session; verify AK X.509 chain, active root and AK fingerprint, signed TPM Quote magic/type, exact SHA-256 selection bitmap and PCR digest derived from all submitted PCR values.
- Enforce operator-pinned, per-platform exact SHA-256 PCR allowlists, reject unknown/rotated policies and forbid client-reported baseline enrollment. Persist short-lived evidence independently of key provenance and Guard trust.
- Provide measured-boot begin/complete/status APIs, Windows/Linux native quote producers, Desktop UI, PostgreSQL migration 0088, negative Go tests and platform build CI.
- No automatic strict Device/Guard elevation. Quote does not prove live JVM/Guard integrity. Physical Windows/Linux TPM validation and full native/backend builds remain requirements for production certification.

## 0.31.1 — Trust Model & Capability Baseline (2026-10-26)

- Enforce server-computed standard/strict Device Trust decisions from verified devices and session binding. Strict fails closed until remote key provenance and Guard runtime evidence are independently verified; no upgrade from local TPM label or historical DB state.
- Sanitize legacy hardware-provenance claims on repository writes and all device/attestation API outputs. Expose deterministic reason codes and an optional HTTP 403 profile requirement without breaking existing status reads.
- Run read-only OS/TPM capability diagnostics through `neverlauncher-api diagnose device-trust|extension-sandbox` with non-zero strict/isolation readiness gates.
- Label all existing extension host processes `legacy-unisolated` and expose actual, limited restrictions and unsupported reasons rather than false `trusted-process` status; show assessments in Admin and Desktop UI.
- Add Go negative tests, native capability probe cross-compilation, three-OS CI and explicit threat model/compatibility limits. OS-enforced sandboxing and remotely verified TPM attestations remain future releases.

## 0.31.0 — Java SDK publication & conditional GA release (2026-10-26)

- Build deterministic Java 17 Maven-compatible Core and source-port Gravit SDK artifacts with POM dependencies, sources, actual generated Javadoc, integrity digests and independent Java consumer smoke tests.
- Fix Gravit compatibility JAR hardcoded version; update JVM Sentry release defaults and retain executable Java Host/Gravit E2E.
- Build and Ed25519-verify real reference `.nlext` packages using the existing Go CLI; intentionally keep test-only fixtures separate from certified production extensions.
- Version the current M01–M19 inventory at 0.31.0 while preserving past release baselines and honest partial/blocked statuses.
- Require exact-commit cross-platform E2E, native Tauri CI and independently Ed25519-authorized evidence before production release signing; reject missing/modified evidence and skipped tests. Full upstream module binary parity and actual GA approval are NOT claimed without required external evidence.

## 0.30.10 — DevTools & Test Isolation (2026-10-25)

- Add executable `nl devtools jar analyze|strip-debug` with bounded, path-safe JAR parsing, classfile constant-pool risk indicators and actual debug-attribute bytecode rewriting; refuse modifications to signed JARs.
- Add `nl devtools component test` with sanitized, time-limited external JVM subprocess, bounded output and Linux bubblewrap OS sandbox as the default. Explicit `--ack-unconfined` is mandatory for process-only testing, which is not a security sandbox.
- Add an opt-in loopback-only test auth fixture server with ephemeral debug identities, control-scoped issue/revoke, strict login, HMAC/TTL checks and real auth event history, without production credential/API access.
- Add executable javac/JVM/HTTP CLI smoke tests, Go race tests and multi-OS CI gates. Sandbox user namespace availability and full production release certification require independent CI verification.

## 0.30.8 — Discord Rich Presence & LAN Discovery (2026-10-25)

- Implement Discord desktop Rich Presence through authenticated local IPC handshake, framed SET_ACTIVITY with nonce-matched acknowledgments, bounded timeouts, reconnection on state changes and optional HTTPS activity buttons. User opt-in, app ID, action URL and activity states are persisted in the native desktop configuration. Discord failures never gate Minecraft launch.
- Implement DNS-SD/mDNS `_neverlauncher._tcp.local.` over real IPv4 multicast with PTR/SRV/TXT/A announcements, multicast discovery, response parsing, source/interface constraints and TTL=0 goodbye.
- Add CLI `nl lan publish|discover|verify` and `nl discord presence` with stdin-driven activity changes. Publishing requires a live TLS backend on the advertised local interface and a matching SHA-256 certificate fingerprint. Discovery TXT fingerprints stay UNTRUSTED; explicit verification requires a separately supplied pin (no trust-anchor mutation).
- Add Go protocol tests (Discord IPC Unix-socket handshake and SET_ACTIVITY ACK, DNS parser corruption and round-trip, TLS pin positives/negatives, CLI fail-closed cases), real multicast+TLS smoke testing, and Windows/macOS/Linux CI; desktop Rust/React builds require CI as they could not be compiled locally.

## 0.30.6 — Trusted JVM Agent (2026-10-25)

- Ship a Java 8-bytecode compatible, executable Minecraft JVM premain agent with signed-plugin classloading, `Instrumentation`/`ClassFileTransformer` hooks and before/after entrypoint callbacks. The plugin runs with **full process privileges**, not a sandbox.
- Reuse the actual signed `.nlext` Ed25519 verifier for agent/plugin bundles. Install to a versioned, SHA-256-addressed directory; activate with a separate atomic record. Validate archive/JAR hashes on each Minecraft launch using an **external publisher trust anchor** and explicit full-access approval.
- Integrate `-javaagent` and original-main forwarding with the existing executable legacy Minecraft launch path; preserve all existing classloader/official-auth compatibility checks. Other launcher routes require their own explicit activation integration.
- Run real Java subprocess tests covering premain, ServiceLoader plugins, Minecraft class-load interception, original game arguments, successful/failed after-main callbacks, tampering and trust-key mismatches; add platform/JDK CI. Full official Minecraft version/loader matrix is not yet certified.

## 0.30.2 — Java SDK Core (2026-10-25)

- Ship dependency-free Java 17+ NeverExtensions SDK Core with an actual runnable HTTP Host Protocol 1.0 client: authenticated hello, periodic heartbeats, identity/protocol validation, loopback-only connection and fail-closed loss of host heartbeat.
- Implement strict manifest 2.0 parsing, SemVer constraints, deterministic transitive dependency resolution with conflicts, optional dependencies, cycle detection and backtracking.
- Add timed asynchronous start/stop execution, lifecycle state transitions, monotonic deadlines, cooperative cancellation with callbacks/child scopes and bounded thread shutdown; timed-out tasks are interrupted and the existing Go supervisor remains responsible for process termination/isolation.
- Supply a runnable and signable Java backend extension, real child-process SIGTERM lifecycle test, and cross-platform JDK 17/21 build/test CI, including a real loopback HTTP test host. Preserve the pinned 0.30.1 audit on newer product versions. Signed package installation and authorization remain managed by existing Go NeverExtensions.
- No claim that standalone Java Host (0.30.4), event/command APIs (0.30.3), JVM agent (0.30.6), or arbitrary Gravit JAR compatibility are implemented here. OS-level sandboxing is not provided by the JVM SDK.

## 0.30.0 — Auth Platform & Protection GA candidate (2026-10-25)

- Reject ambiguous, trailing, unknown and oversized JSON (16 KiB limit) at live OIDC begin/complete, Microsoft linking/logout, password-identity proof, administrator ban and session-revocation entry points. Invalid or empty destructive revocation payloads no longer silently revoke all sessions. The managed SQL/HTTP/OIDC/Microsoft provider activation path now rejects case-colliding and nested duplicate configuration properties before probing or storing a revision.
- Make the executable protection engine fail closed on canceled contexts (including empty/optional-only policy chains), panicking mandatory policy handlers and handler deadlines, without leaking panic payloads. Require an available session store whenever the policy is asked to validate an existing Never session.
- Add real HTTP adversarial tests for ban/no-ban and refresh/session safety; add protection runtime timeout/panic/cancellation regressions. Add a dedicated real PostgreSQL two-replica, PostgreSQL/MySQL/MariaDB, federation provider SDK and Admin build GA CI workflow and require its success before a production release candidate can assemble its bundle.
- Introduce `scripts/ga/assert_go_test_0300.py`: parse genuine `go test -json` events and reject missing/skipped/failed mandatory integration tests rather than treating successful command invocation as sufficient evidence. Test the verifier against malicious/incomplete reports.
- **Certification status:** implementation supplied, **0.30.0 production GA not yet certified locally**. `internal/authrequest` and `pkg/protection` race tests, release version consistency, and Python gate unit tests pass. Full Backend build, multi-database E2E, Microsoft live tenant, and game/ServerBridge matrix require CI or staging evidence. See `docs/releases/0.30.0-auth-platform-protection-ga.md`.

## 0.30.1 — Module Parity Audit & Java API Verification

- Shipped the executable `nl module-parity audit` command with fail-closed source/test inventory for Gravit M01–M19, pinned upstream provenance and honest partial/planned/blocked statuses.
- Added selective real Go/Node test execution with per-module attribution, timeout/skip rejection, and machine-readable SHA-256 evidence; no false full-parity claims.
- Validated the proposed Java type bindings against shipping NeverExtensions protocol types, Go version constants and actual host routes. This is **not** a released Java runtime/SDK.
- Added automated auditor tamper tests and Linux/Node test CI. Historical 0.21.1 locked coverage remains unchanged.

## 0.29.12 — Security & Real Auth E2E (2026-10-25)

- Harden live Admin and Launcher password login and refresh request parsing with a strict 16 KiB limit, exact JSON object semantics, duplicate/case-colliding key detection, disallowed unknown fields, and rejection of trailing JSON. Malformed requests cannot select a different issuer/provider or reach upstream credentials. Oversized requests return HTTP 413.
- Revoke newly created Never sessions and refresh families if access JWT signing fails; after refresh rotation, re-evaluate live role/account/ban/session protection and revoke on denial or token-signing failure. No inactive user may renew access.
- Add real-socket HTTP E2E for multi-issuer identical subject/email isolation, strict routing, invalid password, malicious JSON, separate external/Never credentials, refresh rotation and replay compromise, ban/recovery without resurrecting revoked tokens.
- Add PostgreSQL two-replica real-socket integration: separate SQL repositories, session connections and Federation cores; refresh/replay and ban must propagate without shared in-memory sessions. Add a CI job with actual PostgreSQL 16, MySQL 8.4 and MariaDB 11.4, signed HTTP/OIDC/Microsoft local IdP suites, SDK conformance, migration checks and build/race/vet gates.
- **Verification boundary:** offline race/unit tests of the new standard-library-only auth-request decoder pass. Complete API build and live databases require external Go modules and CI runners unavailable in the local environment; do not represent the new E2E or Minecraft/game-server certification as passed until corresponding CI artifacts are reviewed.

## 0.29.11 — Migration & Compatibility (2026-10-25)

- Add `nl db auth-upgrade preflight|apply|verify`: read-only repeatable-read PostgreSQL account and Minecraft identity scan, privacy-preserving SHA-256 checkpoints, sealed migration application, and post-upgrade preservation verification. Require explicit custom/external provider acknowledgment and reject unsupported local password hashes instead of guessing formats.
- Enforce immutable canonical owner/provider/issuer/subject for existing linked identities at the PostgreSQL boundary via migration `0086`, byte-identical in Backend and CLI. Keep GameProfile UUID immutability from `0081` and explicit account linking/legacy importer semantics.
- Block upgrade if duplicate/corrupt identities, orphaned owners, duplicate names/UUIDs, or drift in users, identity ownership and Minecraft UUIDs are detected. Provide controlled backup/maintenance gates; database rollback requires verified backup restoration, never lossy automatic down-migrations.
- Add repeatable Go tests and PostgreSQL CI for multi-issuer same-subject coexistence, live migration/checkpoint, identity UUID immutability and drift detection. Real PostgreSQL CI certification and Minecraft login/join E2E must be verified independently; see `docs/releases/0.29.11-migration-compatibility.md`.

## 0.29.10 — Admin Auth Provider Wizard (2026-10-25)

- Add a real Admin-managed lifecycle for SQL, signed HTTP, OIDC and Microsoft connectors: real test connection, SQL mapping preview, credential-reference validation, versioned PostgreSQL drafts, transactional CAS activation, rollback and disable.
- Reconcile active provider revisions on authentication paths across API replicas without restart, preserving Federation Core issuer identity and Never RBAC/MFA; failure is fail-closed, and env-configured/local providers cannot be replaced by Admin.
- Require global `settings:manage`, MFA for draft changes, phishing-resistant MFA for activation and audit every change. Reject plaintext secrets and unknown configuration fields. Include migration `0085` in Backend and CLI, Admin UI, regression tests and CI gates.
- **Not certified locally:** full HTTP/API and Admin production builds and real SQL/browser E2E require external dependencies/infrastructure; progressive percentage canary is not included. See `docs/releases/0.29.10-admin-auth-provider-wizard.md`.

## 0.29.9 — HWID Risk & Recovery (2026-10-25)

- Implement voluntary native Desktop machine-continuity hashing, account-scoped server HMAC and 30-day PostgreSQL/Memory retention with scheduled physical cleanup.
- Integrate HWID change into existing session risk assessment as a limited step-up signal; never treat it as immutable identity or an automatic ban condition.
- Support phishing-resistant re-baselining, user appeals, operator approval/rejection fenced to the observed digest, secure device ownership, redacted status and opt-out deletion.
- Add migration `0084` to Backend and CLI, cross-replica PostgreSQL tests and Desktop/UI CI gates. Full external-module/API/Desktop/PostgreSQL E2E remains pending verification; details in `docs/releases/0.29.9-hwid-risk-recovery.md`.

## 0.29.8 — Protection SDK & Policy Engine (2026-10-25)

- Add runtime `pkg/protection` with ordered before/after auth and before launch/join hooks, fail-closed mandatory decisions and explicit allow/deny/step-up/reattest/review semantics. Enforce active bans in the existing federation, token/session, Minecraft and ServerBridge trust paths.
- Implement persistent admin ban/unban/list with reason and optional expiry; user status remains separate. PostgreSQL migration `0083` serializes ban/login races, revokes all associated sessions via the existing `0082` cascade, and is synced with CLI migrations. Protect mutation with `users:manage` plus fresh phishing-resistant MFA and audit each action.
- Add SDK, repository and protection gate regression tests and operator notes. Full SQL/HTTP E2E and live multi-replica/game-server certification are not locally verified: `docs/releases/0.29.8-protection-sdk-policy-engine.md`.

## 0.29.7 — Global Session Revocation (2026-10-25)

- Enforce transactional PostgreSQL cascade of Never session revocation into refresh families/tokens, Minecraft sessions/joins, ServerBridge tickets/handoffs/player sessions/transfers and user jobs across all API replicas.
- Queue real `player.kick` commands to the existing durable ServerBridge control plane when active players lose authorization; guard racing game admission through parent-row locks and permanently fence revoked sessions.
- Revoke sessions and job leases on password, user status, project/global roles, role-definition permissions, device trust/key changes and compromised risk; reject stale/new user or device bindings. Harden HTTP role checks and in-memory role/risk handling.
- Sync sealed migration `0082` between Backend and CLI; add memory, HTTP and PostgreSQL integration tests and CI. Live PostgreSQL/ServerBridge E2E and full API build remain **unverified locally** without external dependencies; see `docs/releases/0.29.7-global-session-revocation.md`.

## 0.29.6 — Provider Runtime Parity (2026-10-25)

- Enforce identical Never MFA assurance for local, SQL, signed HTTP, OIDC and Microsoft runtime logins: upstream AMR/factor labels are retained as non-authoritative provenance and cannot elevate Never sessions.
- Admin password login now uses the configured provider routing before rate limiting and securely persists external credentials, revoking its issued session on storage failure.
- OIDC/Microsoft browser login defers provider credential storage until after Never MFA and session issuance, with safe rollback and issuer-aware responses/audit. WebAuthn continuations keep any pending upstream token AEAD-sealed and commit it only after local passkey proof.
- Add SDK assurance regression tests, Admin/browser provider E2E tests and CI with real SQL engines and race checks. See `docs/releases/0.29.6-provider-runtime-parity.md`.
- Full production certification of live cloud Microsoft identity and licensed Minecraft launch remains pending; tests require an environment with external Go dependencies.

## 0.29.5 — Local Auth, FileAuth & Rehash (2026-10-25)

- Add a real Gravit FileAuthSystem `Database.json` importer: transactional PostgreSQL account + local identity + original Minecraft UUID, dry-run, strict collision refusal and no `Sessions.json`/password/session export.
- Verify explicitly selected legacy password formats inside the existing local connector; after successful known-password proof upgrade Never-owned rows to Argon2id with atomic compare-and-swap, rejecting concurrent resets. Never mutate external providers.
- Enable original Minecraft-name login only for verified imported local account identities. Add an operator CLI using the live Admin API for ordinary account management and protected stdin passwords.
- Add parser/hash regression tests, real PostgreSQL atomic import/UUID/CAS integration test and CI build/test gate. Full runtime/PostgreSQL/Minecraft certification remains pending. See `docs/releases/0.29.5-local-auth-fileauth-rehash.md`.

## 0.29.4 — SQL Mapping & Legacy Hash (2026-10-25)

- Validate real PostgreSQL/MySQL/MariaDB SQL column mapping on provider startup through a read-only, zero-row projection; reject missing columns and binary password/UUID columns without exposing row data.
- Implement explicit Gravit digest and doubleDigest (binary/HEX modes, MD5/SHA-1/SHA-256/SHA-512) and AdditionalHash PHPass ($P$/$H$) verification in the existing live SQL password authentication path, with legacy opt-in, strict encodings and bounded CPU cost. Unsupported hashes fail closed; external passwords are never modified.
- Add PHP cross-checked PHPass vectors, digest/encoding negative cases, real SQL fixture login tests, optional live PostgreSQL/MySQL/MariaDB integration with a dedicated CI workflow, and operator docs. Independent CI/live certification remains pending in this offline environment. See `docs/releases/0.29.4-sql-mapping-legacy-hash.md`.

## 0.29.3 — Provider Routing & Account Linking (2026-10-25)

- Configure explicit, immutable runtime password routing via validated JSON/file policy: exact email-domain selection, strict domain providers, optional explicit-provider requirement and a deterministic default. Auth errors never trigger another connector attempt.
- Apply the same routing decision before HTTP rate-limiting and inside the federation itself; provider IDs are included in per-login attempt limits. OIDC/Microsoft authorization remains explicitly provider-bound and PKCE/state-protected.
- Add enforced provider linking allowlist / global linking disable to existing password and browser proof flows, with active-user verification and issuer/subject collision checks (including Microsoft-specific links). Refreshing already linked credentials stays available and pins identity ID even when new links are disabled; do not link by matching email.
- Normalize duplicate identity collisions to `repository.ErrConflict` in memory and PostgreSQL (including concurrent PostgreSQL uniqueness failures), rather than exposing backend errors.
- Add working Desktop password-provider selection and authenticated password-proof linking UI, plus federation routing/no-fallback, explicit proof/collision and HTTP login/link regression tests, CI gates (including Desktop build), docs and synced version metadata. Live PostgreSQL and HTTP/API E2E require CI dependencies and environment; see `docs/releases/0.29.3-provider-routing-linking.md`.

## 0.29.2 — Auth SDK v2 & Conformance (2026-10-25)

- Enforce one fail-closed capability/implementation validator at real provider registration; block undeclared privileged provider operations.
- Validate identity, profile, issuer, subject, token size and methods at live federation operations, including password, browser, refresh and explicit proof linking.
- Add runnable `RunBehavioral` with dedicated fixtures, wrong-password checks, safe no-secret reports and opt-in provider revocation; retain safe structural `Run` at startup.
- Exercise behavioral conformance against signed HTTP and TLS/OIDC/Microsoft test providers, plus SDK stateful revocation/issuer mismatch checks.
- Upgrade configured SQL/HTTP/OIDC/Microsoft JSON provider lists from legacy arrays or v1 envelopes to a strict v2 envelope at load time, without modifying the original files or secrets.
- Add automated CI formatting, conformance, race and Backend build gates. Details and verification limitations: `docs/releases/0.29.2-auth-sdk-v2-conformance.md`.

## 0.29.1 — Canonical Identity & Issuer (2026-10-25)

- Make canonical auth identity `provider + verified issuer + subject` across the real federation login/link/JIT flows and both repositories; no implicit merging by identical email. Existing external identities keep an isolated legacy provider-scoped issuer unless explicitly linked with fresh proof.
- Preserve ID-token verified OIDC issuer and signed/configuration-checked HTTP issuer. Require exact issuer when selecting ambiguous external refresh credentials; persist encrypted provider credentials per identity, not merely by provider slug.
- Enforce immutable Minecraft GameProfile UUID/ownership in memory, PostgreSQL and a direct SQL guard trigger; mirror migration `0081` in Backend and CLI. Password proof linking requires an active Never session and per-identifier/IP rate limiting.
- Add regression and optional real PostgreSQL tests, rollout guidance and explicit local testing limits. The complete live PostgreSQL + HTTP + Minecraft E2E certification remains pending. See `docs/releases/0.29.1-canonical-identity-issuer.md`.

## 0.29.0 — Production corrections & Real E2E release gate (2026-10-25)

- Restored 11 missing CLI PostgreSQL migrations (0067–0077) byte-identical to Backend, and synchronized embedded first-run deployment templates with the production source of truth.
- Hardened the real NeverRuntime HTTP 429 retry path (`Retry-After`, `X-RateLimit-Reset`, bounded cancellation-aware backoff) and Managed Java archive symlink rejection. Updated repository policy checks for actual call paths and current Java schema 1.3.
- Added a required full Minecraft E2E phase: authenticated internal RCON `save-all flush`/`stop`, real Paper playerdata/plugin data backup and isolated restore via production Host CLI, negative overwrite check and restart-to-healthy verification.
- Added exact-commit production-release dependency on the CI artifact and fail-closed independent evidence checks for real join, replay, handoff and world restoration. See `docs/releases/0.29.0-production-ga-real-e2e.md`.
- **GA certification is pending** until the protected CI, real Docker/Paper, systemd and platform tests provide passing evidence. Locally passing repository/unit tests do not qualify as Production GA.

## 0.28.12 — Provisioning & Operator Workflow (2026-10-25)

- Extended real ServerBridge CLI with local + signed-runtime `verify` (artifact/identity/configuration, Backend heartbeat freshness/version/digest/runtime); offline mode never claims runtime health.
- Added Host Supervisor-based `rollout` with preflight release verification, session-bound stop/start, runtime-health convergence and failure rollback of managed artifact/config; refuses unsafe or unverified process state.
- Protected operator mutations with an exclusive file lock and strengthened rollback against forged transaction IDs, world-file targets, symlink escapes and mismatched active transactions; deployment now rejects non-loopback HTTP credentials.
- Added a real Admin ServerBridge public-key enrollment workflow, gated by global `settings:manage`, using the existing authenticated Backend registration API without transmitting node private keys.
- Added Go and Admin negative tests, operational documentation and explicit limits around systemd-managed rollouts and real Minecraft runtime certification. See `docs/releases/0.28.12-provisioning-operator-workflow.md`.

## 0.28.11 — Service Installers & Watchdog (2026-10-25)

- Added real `server-bridge host service install|uninstall|start|stop|restart|status` systemd lifecycle for unprivileged user services and explicitly privileged system installation (Host JVM supervisor and scoped HTTPS RemoteControl agent).
- Host `run` now implements sd_notify READY/STATUS/STOPPING and identity-aware WATCHDOG, plus graceful systemd SIGTERM forwarding to the existing session-bound Minecraft `stop` mechanism.
- Installed system units use a dedicated non-root account, capability drop, no-new-privileges, protected mounts, cgroup stop semantics, controlled timeout, safe unit generation, exclusive installation and rollback on systemctl failure.
- Added Linux socket, unit policy, installer lifecycle, race and live process/notification E2E regression tests. Windows installer intentionally unsupported; actual systemd PID 1 and Minecraft world E2E still require deployment validation.
- See `docs/releases/0.28.11-service-installers-watchdog.md`.

## 0.28.10 — Game World Backup & Restore (2026-10-25)

- Implemented Host CLI `server-bridge host world-backup create|list|verify|restore` with separate private storage, real file-level SHA-256 snapshot verification and atomic isolated restore. The game world, UUID playerdata, plugin data and selected configurations are copied as files, not as Backend/storage backups.
- Use confirmed Host Supervisor console `stop` and clean exit as the only supported running-server consistency policy; refuse crashed, unverified and force-killed process states. No unsafe unacknowledged online snapshot and no implicit post-backup restart.
- Added strict path/symlink validation, an OS-identity exclusive operation lock, manifest verification, no-overwrite restoration, Go negative tests, and a real CLI subprocess integration fixture in CI.
- Explicit limits: no Minecraft runtime test with actual player login/inventory restore, no Admin/RemoteControl world-backup API and no automatic offsite retention in 0.28.10. See `docs/releases/0.28.10-game-world-backup-restore.md`.

## 0.28.9 — Backend Operations (2026-10-25)

- Added instance-scoped, globally authorized Backend Operations workspace with verified version/commit/uptime, storage/repository health, runtime identity and current operational-config revision. Existing validate/apply/restore and build/sign/extension/session lifecycle flows are reused, not duplicated.
- Added read-only recent Admin and Minecraft launcher session observability from actual session stores, excluding tokens and distinguishing recent auth activity from live sockets.
- Added `backend:control` + fresh MFA operational-settings reload and persisted user-targeted notifications with actor-bound idempotency, per-recipient poll/ack, 24-hour expiration and an Admin inbox. It is not in-game/Desktop push.
- Added opt-in supervised Backend restart: random per-runtime identity, fresh phishing-resistant MFA, exact confirmation, PostgreSQL once-per-instance journal (migration `0080`), no shell or PID execution, and graceful HTTP drain. Process recreation is exclusively the external supervisor's responsibility.
- Added schema migration to both API and CLI catalogs, Admin regression tests and Go lifecycle/key/validation tests. Full Go API and PostgreSQL/systemd E2E verification are not yet certified (missing modules / infrastructure).
- Operational guide: `docs/releases/0.28.9-backend-operations.md`.

## 0.28.8 — Network Panel & Topology (2026-10-25)

- Introduced a working network panel in the existing ServerBridge Workspace displaying the runtime-learned proxy/backend topology, signed routing state, freshness of observations, reservations, player load and active route status from PostgreSQL.
- Added project/server-authorized, fresh-MFA network admission limit changes (`gameserver:traffic`). The operator ceiling is stored independently of node-signed max players; `null` clears it, `0` blocks new admissions. Optimistic policy revision and exact runtime precondition prevent stale operator writes.
- Applied the ceiling to actual route discovery, single-use handoff issuance, handoff redemption and direct join redemption, plus topology status. Changing policy invalidates outstanding handoffs in the same transaction. Legacy handoffs cannot bypass active capacity policy.
- Reused existing ServerBridge `server.maintenance` and `server.drain` command flows (signed runtime capability, idempotency, Bridge ACK) without changing frozen Protocol v3 or inventing remote shell operations.
- Added Go validation/capacity tests and browser API regression tests. **The full API suite and PostgreSQL multi-node E2E cannot be certified without external Go modules and a running PostgreSQL server.** Live Minecraft proxy E2E and Admin dependency installation also remain outstanding.
- Operator guidance: `docs/releases/0.28.8-network-panel-topology.md`.

## 0.28.7 — Authlib / ServerBridge Integration (2026-10-25)

- Bind runtime-observed Minecraft UUID to the authoritative UUID in the ServerBridge join ticket before redemption; never echo request UUID as authoritative player identity. UUID disagreement fails closed without consuming the ticket or proxy handoff.
- Verify the full structured Java Backend response (node/name, UUID, accepted admission mode, player correlation) instead of searching JSON for `"allowed":true`. Verify proxy-to-backend handoff target/source, UUID-associated session correlation, one-time handoff ID and 30-second expiry.
- Velocity and BungeeCord/Waterfall now compare the UUID obtained **after Minecraft authentication** to the join ticket's UUID. Proxy handoffs require this authenticated binding; clear pending/confirmed identities on disconnect/reload/shutdown.
- Join/handoff use a single Backend attempt: do not replay a non-idempotent one-time operation across replicas when the first response might have been committed. Legacy `failMode=open` can no longer allow bypassing ticket authentication.
- Introduce dependency-free live bridge Java harness and Go UUID tests. **No claim of real Mojang/game client runtime E2E or full Gradle/API integration certification.** See `docs/releases/0.28.7-authlib-serverbridge-integration.md`.

## 0.28.6 — Adapter Capabilities & Certification (2026-10-25)

- Enforce signed runtime-advertised per-command capabilities in live Backend create/delivery and Java Bridge execution; absent/stale/unsupported claims fail closed without granting Host/Backend control.
- Reject overclaimed adapter capabilities, uncertified hybrid cores and unknown adapter flags in the signed runtime identity verification path. Correct Sponge flags; never treat Vanilla RCON as a pre-login gate.
- Surface fresh signed capabilities to project-scoped Admin; filter actions by permissions **and** runtime support. Add Java 14-platform capability harness and Go/Node negative tests.
- Keep ServerBridge v3 frozen; artifact certification now explicitly states its scope and coverage. Real target-version Minecraft login/server runtime certification was not executed in this source delivery.
- See `docs/releases/0.28.6-adapter-capabilities-certification.md` for verification and rollout.

## 0.28.5 — Durable Commands & HA Fencing (2026-10-24)

- Closed the production ServerBridge HA redelivery hole: when a delivered PostgreSQL command loses its lease/ACK or runtime identity, it becomes terminal `indeterminate`, not another executable queued command. Pending commands that expire before delivery remain `expired`. Implemented in both SQL and in-memory stores, including Admin history and command reads.
- Reused PostgreSQL transactional row locks and Redis coordinator checks; signed Java ServerBridge v3 envelopes now expire no later than their particular delivery lease. An overdue/delayed signed HTTP response is no longer executable.
- Applied migration `0078_control_ha_fencing_0285` to both API and CLI catalogs: repair uncertain legacy rows and install a PostgreSQL trigger fencing old Backend versions from recycling prior delivery ownership. Do not run older Backend code against this database expecting automatic redelivery.
- Added cross-replica PostgreSQL integration tests (requires explicit test DSN), lease-loss/runtime-change regression tests, and local Host `remote inspect` which reports durable receipt and observed process state without replay or false success claims.
- Kept local Host RemoteControl idempotency/durable journal separate from Game Server authorization and Backend control; cross-host PostgreSQL/Redis Host orchestration and real Minecraft E2E remain unverified / future work.
- Operational details in `docs/releases/0.28.5-durable-commands-ha-fencing.md`.

## 0.28.4 — RemoteControl Agent & Security (2026-10-24)

- Implemented a real, standalone HTTPS host RemoteControl agent using the existing Host Supervisor `start`/`stop`/`restart` operations and verified runtime status; no remote executable/shell/Java argument API is exposed.
- Add explicit local node initialization, a protected HMAC-SHA256 node identity, short-lived node-bound service tokens with exact host-level scopes and CIDR restrictions, explicit local revocation and live key rotation; credentials are never placed in query strings or printed by the CLI.
- Require TLS 1.3, server certificate verification for the remote CLI, optional client-certificate verification, a network source allowlist, and private token/key files. Reject unauthorized operations without dispatch.
- Persist idempotency intents **before** executing external effects and successes after proof; replayed requests are read from a protected command journal and uncertain outcomes are `indeterminate` and never silently rerun. Enforce a single active agent lease for each server root, append a restricted audit log.
- Add real HTTPS CLI, negative authorization/replay/concurrency/rotation/revocation tests and an integration test that remotely stops a real supervised POSIX JVM fixture. Live Minecraft cluster, complete repository CI and Backend-to-agent orchestration are not claimed.
- Operator guide: `docs/releases/0.28.4-remotecontrol-agent-security.md`.

## 0.28.3 — JVM Launch Profiles (2026-10-24)

- Execute real `java-main-class` and `java-module` profiles through existing Host Supervisor alongside compatible `java-jar` and Forge/NeoForge `java-args-file`; provide explicit and auto-inferred launch modes, canonical classpath/modulepath entries and actual Java argument arrays.
- Reject escaping paths and symlinks (checked on configure and execution), invalid Java main/module identities, JVM agent/response-file injection, and unapproved game arguments. Explicit custom Java executable selection requires local host-level opt-in.
- Validate optional Forge `user_jvm_args.txt` against approved JVM flags and materialize tokens into the command array to avoid a JVM re-read of mutable user args.
- Add Go tests for actual Java classpath/JPMS execution, fake-process argv, malicious paths/flags, and 0.28.2 Host lifecycle regressions. The full CLI suite and live Minecraft E2E were not completed.
- See `docs/releases/0.28.3-jvm-launch-profiles.md` for examples, security boundaries and scope.

## 0.28.2 — Host Supervisor 2.0 & Recovery (2026-10-24)

- Reworked the existing ServerBridge Host runner: verified Linux/Windows process birth identities, session-scoped graceful stdin `stop` followed by bounded signal fallback, and explicit recovery that refuses to adopt a still-running orphan or kill a reused PID.
- Isolated game JVM environment with an allowlist and restricted working directory, redacting explicitly configured env values from CLI status and configure output.
- Added crash-loop restart windows, exponential backoff, three rolling log streams, rotation-aware `logs --follow`, and observable stale/orphaned host state.
- Added executable Go subprocess integration tests (command lifecycle, logs, recovery, stale requests, env controls) and Windows cross-compilation check. No claim of complete CLI suite, Minecraft runtime E2E, reboot autorun, cgroup/Windows Job Object containment, or host service installer.
- See `docs/releases/0.28.2-host-supervisor-recovery.md` for commands and explicit safety boundaries.

## 0.28.1 — Control Domains & RBAC (2026-10-24)

- Enforce per-command, live RBAC for every ServerBridge v3 mutation (`gameserver:broadcast`, `gameserver:moderate`, `gameserver:save`, `gameserver:traffic`, `gameserver:shutdown`, `gameserver:console`). Legacy `serverbridge:control` and `serverbridge:console` no longer grant any command automatically.
- Keep Backend, Host process and Host exec as distinct **global-only** permission domains. No Backend restart or shell/host execution route is exposed through game control.
- Require fresh MFA plus server-side project visibility and the exact command right before dispatch, with denial audit; re-check project/command permissions before returning a journal entry; remove unauthorized commands from scoped overview.
- Project-owner wildcards are projected as known project actions in Admin rather than leaking `*` to non-project domains. The action dropdown reflects actual rights, including retries of previously pending commands.
- Apply migration `0077` with explicit legacy admin/operator game-only grants, leaving custom roles unchanged. No Backend/Host privileges are migrated.
- Preserve frozen ServerBridge Protocol v3 payloads, node identity, command leasing and idempotency.

## [0.28.0] — Client Factory GA integration (source implementation)

- Repaired executable `certify-matrix` CLI routing; added fail-closed `certify-ga` and independently signed matching-server join attestations bound to exact release version and commit.
- Added protected five-family native E2E release gate and exact-commit GA evidence verification in production release-candidate workflow; missing or failed live evidence blocks release.
- Admin Client Factory export now stages and validates the complete ZIP before returning it, preventing partial HTTP downloads and detecting tampered files, unsafe paths and symlinks.
- Synchronized versions; corrected the outdated Quilt error expectation and restored the explicit platform-signing dependency checked by Release Doctor.
- This is a source implementation; live Minecraft, complete repository CI and platform signing are mandatory before declaring production GA.

## 0.27.12 — Runtime E2E & Certification

- Added executable `runtime client-factory certify-run`: verify pinned InstallPlan and adapter identities, clone immutable files into an isolated temporary test directory, launch the actual Minecraft JVM through hash-pinned NeverRuntime, check exact Java/profile/classpath/OS target and Minecraft process startup evidence.
- Added Ed25519 signed runtime certificate and strict `certify-verify`: bind observed Java/runner digests, probe JSON and runtime log SHA-256 to the exact reproducible InstallPlan; changes to any managed output or proof revoke validity.
- Added fail-closed `certify-matrix` with signed per-target verification, exact loader/version/OS/arch checks and default mandatory coverage of all five loader families.
- Added adversarial Go tests (wrong Java, fake success, tampered output, wrong signing key, missing target, altered log), separate real-upstream CI jobs and a runnable graphical Minecraft E2E entry point.
- Note: local tests certify *verification logic and HTTP fixtures*, not live Minecraft. CI live GUI and matching-server scenarios are separate gates and must actually pass before production certification can be claimed.

## 0.27.11 — Adapter Lifecycle & Compatibility

- Record separately versioned executable adapter pins (`id`, independent version and embedded-source SHA-256) inside the immutable InstallPlan.
- Fail closed on adapter fingerprint drift during replay; opt in to actual re-materialization with `--upgrade-adapters=true`, validating locked runtime, source hashes and final outputs before atomic replacement.
- Add `runtime client-factory adapter-inspect` and `adapter-verify` for binary/lockfile comparisons and strict integrity verification.
- Keep older unpinned lockfiles readable without assigning fictitious adapter history; block them from strict verification and modpack redistribution until an explicit upgrade.
- Add target/Java compatibility checks, including strict Java 8 handling for classic Forge 1.7.10/1.12.2; add executable regression tests and cross-platform CI.
- No claim of Minecraft runtime certification: that requires real client/server runs in 0.27.12.

## 0.27.10 — Visual Client Factory Builder

- Added real authenticated, workspace-scoped API execution of the existing Client Factory CLI, durable jobs with polling/logs/cancellation, exact-version input enforcement, isolated per-job directories, bounded concurrency, verification and restricted export.
- Added React Client Factory source wizard for Vanilla/Fabric/Quilt/Forge/NeoForge and Modrinth/CurseForge ZIP uploads, with pinned workspace checks, InstallPlan source/output/processor inspection, SHA-256 job diff and operator download. Existing Build Workspace release flow stays intact.
- Configured API Docker image to include the CLI and Java runtime and a dedicated factory volume in production Compose; added API, CLI, Admin and container CI gates and operator documentation.
- Scope limitation: previews show exact input configuration before materialization (not fully resolved upstream dependency graph); no automatic promotion into a signed release, sandbox certification, or real Minecraft GUI launch is claimed.

## 0.27.9 — Authlib & Classloader Compatibility

- Introduced executable, receipt-verified classloader compatibility configurations. `runtime client-factory compat-apply --client-dir ... --file ...` copies exact SHA-256-pinned local JARs through transactional staging; the immutable receipt, sources and modified InstallPlan digest prevent silent mutation. `compat-inspect`/`compat-verify` validate every pinned byte.
- Extended existing Java 8 `legacy-run` to use verified additional classpath and JVM Java agents, with explicit official/offline/Yggdrasil authentication policies and required token/UUID for authenticated modes. Agent JARs must contain a valid `Premain-Class` manifest. Java 9+ modulepath and `--add-opens` are strictly validated and pinned but are not claimed as end-to-end launched modern clients.
- Added audit-preserving authlib overlays: exact before/patch/after SHA-256, retained patch JAR bytes, chained transformation provenance, signed-archive rejection and strict whole-client verification at subsequent launch/rebuild. Unknown class transforms and Java 17 bridge rewrites are not silently accepted.
- Added integration tests for transactional application, Java argv execution, invalid agent files, replay isolation, corrupted lock/artifacts, wrong hashes, failed transformation rollback, legacy regressions and CI. Real Minecraft GUI login and legacy bridge/modern module launch remain outside certification.

## 0.27.8 — Legacy Client Adapters

- Integrated executable legacy launch adapters into Unified InstallPlan for original Vanilla 1.0–1.12.2 profiles and Forge 1.7.10/1.12.2. A generated `.neverlauncher/legacy-launch.json` contains checked parent/child version-profile identities, inherited game arguments, exact ordered classpath with SHA-256, platform native directories, Forge LaunchWrapper tweaker and Java 8 requirement. The recipe and artifact hashes are bound to InstallPlan and revalidated on rebuild/launch.
- Added `runtime client-factory legacy-inspect` and `legacy-run` commands. Legacy Java 8 execution verifies the entire InstallPlan before launching, enforces an actual `java -version` check, resolves the host's OS/arch and native directory, and supplies game arguments through `exec.CommandContext` with no shell. The optional official access token is read from `NEVERLAUNCHER_MINECRAFT_ACCESS_TOKEN`, not logged or serialized in the lockfile.
- Fixed legacy classpath resolution to retain child-before-parent ordering, replace inherited group/artifact versions, exclude server-only and classifier-native artifacts, and reject missing/modified libraries. Java 8 legacy materializers, upstream SHA verification, Forge universal extraction, native materialization and transactional publication from earlier versions continue to do the real installation work.
- Kept old 0.27.7 InstallPlan receipts readable and rebuildable without silently rewriting their immutable identities. For the new verified launch recipe, build into a new clean destination.
- Added offline HTTP-backed Vanilla/Forge end-to-end installer fixtures, exact replay/hash-tamper coverage, Java subprocess argv tests and cross-platform CI. **This does not implement automatic conversion to Cleanroom, lwjgl3ify or Java 17+ legacy bridge targets:** their upstream-specific replacement classloaders, bootstraps, patches and pinned artifacts require separate verified importers and runtime E2E before parity can be claimed. No real Minecraft GUI launch or gameplay session is certified by fixtures.

## 0.27.7 — Shared Libraries, Assets & Natives

- Implemented opt-in, content-addressed shared Maven/library/native and asset cache in actual Vanilla/Fabric/Quilt/Forge/NeoForge download workers, with SHA-1 and SHA-256 verification, atomic concurrent cache insertion and independent verified client copies. Added `--shared-cache-dir` for Client Factory, direct materializers, modpack import and workspace builds.
- Fixed multi-target native materialization: one native JAR may serve several target architectures, but each target receives its own extraction. Reject unknown classifier architectures and conflicting native outputs instead of silently replacing existing binaries.
- Reject incompatible Java library revisions for the same target in Mojang metadata before materialization; preserve target-disjoint libraries and native classifiers.
- Added functional HTTP-backed shared-cache and dual-Windows-target native fixture tests, tamper and conflict tests, cross-platform CI, and operator documentation in `docs/releases/0.27.7-shared-libraries-assets-natives.md`. These tests do not certify actual Minecraft launch on every supported OS.

## 0.27.6 — Manual Artifacts & Permission Gates

- Added verified nested/flat `--manual-dir` recovery with symlink rejection, upstream SHA validation, explicit acquisition provenance and machine-actionable missing-file codes/hashes. Import stays atomic and fail-closed on untrusted metadata, missing files and hash errors.
- Added independent exact-pack/exact-path/exact-SHA256 redistribution policy gates, `--distribution redistributable`, `--permissions-file`, and `verify-publication` against the installed immutable InstallPlan and import receipt. Unsupported/unknown policy fields and conflicting grants fail closed.
- Added `export-modpack-artifacts` with mandatory gate, content rehash during ZIP stream, atomic non-overwrite creation, and **artifact-only** packaging, excluding Minecraft runtime/loader content. All rights records are operator assertions, not independently validated legal grants.
- Fixture/integration tests for Modrinth, missing/manual recovery, grant rejection, import-time blocking, tamper verification and export. CI workflow for Linux/Windows/macOS; see `docs/releases/0.27.6-manual-artifacts-permission-gates.md`. Live Minecraft launch, third-party legal authorization and upstream permission checks require external verification.

## 0.27.5 — Modpack Import Engine

- Working `runtime client-factory import-modpack` for Modrinth `.mrpack` and CurseForge ZIP manifests; builds pinned Minecraft/loader through the existing Unified InstallPlan materializers, then stages every verified package artifact and publishes only after checking the full result.
- `inspect-modpack` local archive preflight; Modrinth client/server optional rules, `overrides` and `client-overrides` layer precedence; CurseForge project/file metadata and permitted download URL resolution.
- SHA-1/SHA-512 verification for Modrinth; CurseForge API SHA-1 verification; SHA-256 provenance and immutable InstallPlan receipt for imported output; manual verified artifact fallback, missing report and fail-closed publication.
- Limits and safety: ZIP path/mode/collision validation, constrained decompression/downloads, untrusted URL validation, private temporary workspace and atomic release, rejection of managed-path overrides.
- Local HTTP-backed end-to-end fixtures and regression tests. Real Minecraft launch and hosted CurseForge production API access are **not** certified by fixture tests.

## 0.27.4 — MirrorHelper Command Parity (verified executable operations)

- **Client Factory commands:** `install-client` and `launch-installer` execute the existing pinned Vanilla/Fabric/Quilt/Forge/NeoForge materializers; Forge/NeoForge continue using the 0.27.3 isolated processor worker. Verified local installer JARs can seed the Forge/NeoForge build without fetching a second, potentially changed copy.
- **Source-verified downloads:** `download-installer` pins a specific Forge/NeoForge artifact SHA-256 into an external cache; `install-mods` materializes SHA-256-verified client JARs from HTTP/local manifests or exact Modrinth version IDs, recursively resolving required compatible project dependencies; `lwjgl-download` derives the exact Maven path, verifies bytes and optionally registers a non-classifier library into the active runtime profile. Classifier natives require explicit target rules and remain download-only.
- **Workspace execution:** `workspace` validates a strict local JSON recipe; `apply-workspace` executes a complete Client Factory materialization and verified mod installation into unpublished staging, then publishes the finished tree. No unverified remote scripts or auto-executable workspace fragments.
- **Integrity-preserving mutations:** `patch-authlib` applies only bounded `com/mojang/authlib/*.class` overlays to a verified base jar and requires SHA-256 for base, overlay and final result. `dedup-libraries` creates hardlinks for identical library JARs without deleting classpath entries. All commands validate the prior InstallPlan, use a sibling transaction, update output hashes/provenance and refuse unsafe inputs.
- **Scope:** these are working CLI commands with offline HTTP/Java-worker integration tests, not a claim of byte-for-byte GravitLauncher module compatibility. CurseForge/Modrinth project-ID fetching, permission-driven missing artifact UX and full native target adaptation are scheduled for 0.27.5–0.27.9. No live authenticated Minecraft session/graphical client E2E or strict bubblewrap execution is certified in this environment.

## 0.27.3 — Isolated Build Worker & Recovery

- **Executable out-of-process workers:** Forge/NeoForge processors now execute in a short-lived subprocess launched from the same CLI binary. The worker receives a bounded JSON request, has a scrubbed environment, restricted temporary directory and bounded diagnostic log; Java has a bounded heap and hard wall-clock timeout. Linux and macOS enforce CPU, file size and descriptor rlimits; Windows uses process-tree termination.
- **Cancellation and crash containment:** Linux parent-death signal, process-group teardown, worker exit/status logs, ephemeral worker directories and journaled processor completion. Existing materializers and Client Factory use the same execution path; no API/CLI process executes upstream Java processors in-process.
- **Strict Linux filesystem/network sandbox:** `--processor-sandbox required` uses bubblewrap with a private root, only the client staging root writable and a disconnected network namespace. Missing bubblewrap or unavailable namespace support fails closed without unsafe fallback. Default `process` mode preserves existing compatibility, but is **not** a host-filesystem or network sandbox.
- **Tamper-safe recovery:** journal schema 1.1 binds each processor to SHA-256 of Java and all input JARs, quarantines incomplete/corrupt outputs and disallows symlinks and paths outside client root before accepting outputs. Previous journal format is invalidated and processors are safely rerun.
- **Validation:** offline Forge/NeoForge and Client Factory integration tests, real child worker/cancellation/log fixtures, input/output tamper tests, cross-compiled Windows/macOS binaries, Go vet. Live Minecraft client starts and namespace-enabled bubblewrap execution still require external certification.

## 0.27.2 — Modern Loader Adapters

- **Executable modern adapters:** Hardened Vanilla release/snapshot selection, Fabric/Quilt Meta API compatibility and Maven identities, Forge/NeoForge version input safety, and library source conflicts in the actual materializers used by Client Factory.
- **Deterministic resolution:** unsorted upstream lists, pre-release numbering and Fabric `+build.N` suffixes now resolve deterministically; `latest` and `latest-stable` have distinct policies. Special-character Minecraft IDs are correctly URL-encoded.
- **Pinned provenance:** Client Factory now captures Vanilla release type, exact resolved loader and Maven/intermediary identity, preserves existing resolution hashes and blocks replay drift. No silently updated loaders on rebuild.
- **Verification:** offline HTTP materializer/processor/recovery fixtures, malformed metadata and URL-safety regressions, Go CLI build, vet and Windows/macOS/Linux CI recipe. Real Minecraft GUI/client-server certifications remain pending.

## 0.27.1 — Unified Client Factory InstallPlan Engine

- **Working Client Factory:** `runtime client-factory build|verify|inspect` reuses the real Vanilla, Fabric, Quilt, Forge and NeoForge materializers to install into a sibling staging directory and publish only verified output trees.
- **Immutable reproducibility:** canonical plan includes pinned versions, URL/SHA-256 source provenance, Forge processors and outputs, resolved metadata, Java/OS/architecture targets, launch metadata, exact output hashes and reproducibility identity. Rebuild rejects modified files, loader metadata drift and unexpected outputs.
- **Execution integration:** actual download tasks and processor completions feed the shared plan recorder; existing materializer commands and release workflows stay backward-compatible.
- **Tests and release scope:** offline real-HTTP materializer integration tests for five loader families and rollback/tamper checks; cross-platform CI workflow and operator documentation. Full external-installer sandboxing, modpack import, visual UI and real graphical/client-server certification are later roadmap milestones. This source change is not a signed or independently certified production release.

## 0.27.0 — Official Minecraft Authentication GA release gate

- **Production hardening:** prevent an interrupted legacy-to-multi-account OS-vault migration from replacing a newer native credential or retiring its only recoverable source before verifying a readable destination; zeroize partial keyring reads on errors.
- **Real release admission:** fail-closed Ed25519 verification of six independently collected *live* browser/device, Minecraft sessionserver, vanilla/modded world join, OS vault/lifecycle and signed native installer attestations for the exact release commit; stale/mocked/unsigned/mismatched evidence is rejected. Six SHA-256 hashes must also match the exact native archives imported into the shipping bundle.
- **Signed delivery integration:** `build-release.sh` and the production-release-candidate workflow now require the independent official-Minecraft evidence before producing a 0.27.0 signed bundle; existing Authenticode, notarization, signed release hashes and public delivery verification remain mandatory.
- **Version/documentation:** synchronized 0.27.0 package/version/OpenAPI metadata; CLI provider reports identify 0.27.0; updated operator execution, migration, signing, rollback and testing procedures.
- **External GA blocker:** own-app Minecraft Services approval, real native keyring runs and actual online-mode Java server joins have **not** been certified in this source-only environment. The changes do not claim that a signed GA build or provider approval exists.

## 0.26.12 — Official Integration & Compatibility Certification Preflight

- Added live Minecraft Java sessionserver `join` + `hasJoined` verification on the same official bearer and subject obtained through Microsoft's OAuth → Xbox Live → XSTS → Minecraft Services chain. Real ephemeral RSA/AES challenge and Java signed SHA-1 hash; identity mismatch and upstream rejection block the POC result.
- Added non-credentialed Minecraft 1.20.2+ online-mode server Encryption Request probe and an actual server-log evidence checker that binds the official UUID digest to a successful player login with `online-mode=true`; optional Fabric/Forge/NeoForge loader startup checks.
- Added negative and adversarial tests for provider HTTP, failed join/hasJoined, mismatching official UUID, callback pollution, offline server responses and file evidence rules, with privacy-safe reporting.
- Added Windows/Linux/macOS Go + native Tauri/Rust + renderer CI matrix. Unit/fixture/build success does not constitute external provider approval or a real successful Minecraft client login.
- **Live certification pending:** own Microsoft app approval, actual Windows/Linux/macOS vault operation, and real vanilla/modded authenticated client-to-server joins require operator-owned accounts/servers. No such credentials, server logs or platform test stations were provided. See [operator procedure](docs/releases/0.26.12-official-integration-certification.md).

## 0.26.5 — Native Xbox & Minecraft Token Exchange

## 0.26.11 — Admin Official Provider Management

- PostgreSQL-backed Microsoft public Client ID, personal-account issuer policy and browser/device flow controls with CAS revisions and immutable history.
- Admin controls require global settings authorization and recent MFA. Native login/refresh and Backend legacy flows now honor the live provider policy.
- Bounded network diagnostics for Microsoft, Xbox and Minecraft Services with security-safe audit events; provider approval remains unverified until real account POC.


- Browser PKCE and Device Code grants are now exchanged **inside Rust/Tauri** rather than on the Go Backend. Native code performs Microsoft access → Xbox Live → XSTS (Minecraft relying party) → Minecraft access and checks entitlements plus the verified Java profile.
- Native-only credential vault schema 2 stores the Microsoft refresh token, Minecraft bearer/expiry and the registered Client ID; no bearer, code, verifier or Backend session ticket crosses renderer IPC. Old schema-1 keyring records remain usable without silent account substitution.
- Integrated native refresh and rotation for status, Minecraft skin/cape actions and NeverRuntime online launch. Checks the Never session and configured client ID, verifies the Java UUID remains stable, and never promotes Yggdrasil/offline accounts to official.
- Added native Device Code polling with cancellation and backoff, post-redemption retry without reusing Device Code, provider error classification (XSTS family/region/account and invalid Minecraft app registration), deterministic real-HTTP local provider fixtures, native CI on Windows/Linux/macOS and the operational runbook.
- **External approval and real Minecraft online-mode login remain unverified.** Native Rust toolchain and some Go HTTP API dependencies are unavailable in the current environment; CI and real provider E2E remain mandatory release gates.

## 0.26.4 — Device Code Fallback: Native Polling & Recovery

- Device Code now starts an automatic **native Rust/Tauri waiter** in Desktop. It respects the initial Microsoft polling interval, handles backend `202 authorization_pending` and `slow_down` interval rotation, and stops on verified Minecraft profile, cancellation, denial, provider expiry or Never authentication failure. Browser OAuth/PKCE remains the primary login.
- Implemented bounded exponential backoff on network/temporary HTTP failures (408/429/5xx), honoring numeric `Retry-After`. Transient failures do not discard a valid pending device flow; the waiter automatically resumes until it expires. Nonrecoverable OAuth errors stop polling rather than retry indefinitely.
- Added resumable post-redemption Backend continuation: a successfully redeemed Microsoft one-use Device Code is not redeemed again after a transient Xbox/XSTS/Minecraft outage. Short-lived Microsoft credentials stay sealed in authenticated AES-GCM flow tickets and are zeroized after native use; permanent denials still stop the flow.
- Fixed native flow replacement/cancellation races. A random flow nonce and in-flight guard prevent old requests from inserting late pending tickets or connecting a canceled account; a Tokio watch channel interrupts the waiter during its delay **or** ongoing HTTP call. Active flow tickets remain in native memory, are zeroized on removal, and are never returned to React.
- Updated the Desktop UI with explicit verification URL/user code, automatic progress, remaining lifetime and cancel button; removed the manual poll action. Added native cancellation/expiry/backoff tests and renderer success/late-result/race regressions, plus platform build CI.
- **No claim of external approval:** real Microsoft app access to Xbox/Minecraft Services, real OS keyring tests and official online-mode server login still require actual credentials, platforms and a certified environment. Source tests are not a live provider E2E.

## 0.26.3 — Browser OAuth + PKCE

- Implemented native Rust/Tauri desktop Authorization Code + PKCE S256 sign-in using the **system browser** and a dynamically bound IPv4 loopback HTTP callback. The native manager generates fresh cryptographically random verifier/state per attempt, verifies exact Host/path/HTTP method and OAuth state, detects duplicate query parameters, limits callback input, accepts one successful grant, times out and supports cancellation.
- Connected native browser login to the authenticated Never Backend: its configured **own** Microsoft public client ID is fetched natively; code + verifier are exchanged on the Backend through Microsoft → Xbox Live → XSTS → Minecraft Java profile. No renderer-owned OAuth verifier, authorization code, refresh token, Minecraft bearer or encrypted ticket.
- Store resulting opaque session in the existing OS vault; the official profile is the only login result returned to React. Preserved restore, refresh, launch and texture operations with the native security boundary from 0.26.2.
- Promoted browser PKCE to the primary Desktop login action and retained Device Code as an explicit fallback. Cancel also closes the native login flow and prevents late results from being linked.
- Added provider-chain fixture tests, malformed grant tests, real loopback callback/cancellation Rust tests, privacy/race renderer tests, CI and an operator runbook.
- **No external approval claim:** real Microsoft application registration, own-app Minecraft Services authorization and live game account testing remain release blockers. This sandbox cannot perform a native Rust build or full Backend suite due unavailable Rust and third-party dependencies.

## 0.26.2 — Native Identity & Security Boundary

- Migrated Desktop official Minecraft Device Code, polling, profile, cape/skin operations from renderer fetch/session ticket to native Tauri HTTP requests; renderer receives no official flow tickets, refresh tokens or game access tokens.
- Added a functioning Rust Official Identity Manager backed by the operating system credential store, scoped to Backend origin + Never session; no plaintext storage fallback. Linked sessions persist across Desktop restart when the Never session is still valid.
- Routed official launch credential retrieval through the manager directly into NeverRuntime; rejected renderer-supplied MSA credentials, mixed identities and official offline launch.
- Bounded official API responses, disabled HTTP redirects, required HTTPS (except loopback development), validated profile IDs, enforced Device Code polling/expiry and propagated rotated session tickets atomically to the vault.
- Implemented user-initiated cancel/disconnect, safe session restore and native texture operations; added renderer privacy tests and Rust validation tests.
- **External provider gate remains unresolved** until the operator runs the actual own-app POC and real Minecraft account/server checks. Rust compilation and real keyring integration require CI/native builders; no provider credentials were supplied for live E2E.

## 0.26.1 — Official Minecraft Provider POC & External Approval Gate

- Added executable `official-provider-poc` command that validates NeverLauncher's **own** Microsoft Entra public-client ID using live personal-account Authorization Code + PKCE (system browser, loopback callback) or device-code fallback; no new authentication UI or local-account impersonation.
- Reused the existing production Microsoft → Xbox Live → XSTS → Minecraft chain; added explicit safe stage observer, Microsoft refresh test, real Minecraft `mcstore` entitlement request and Java profile verification.
- Added real Minecraft app-registration rejection classification (`invalid_app_registration`) and token-free, private, per-stage JSON evidence reports; a Microsoft/Xbox-only success never marks Minecraft Services accessible.
- Added callback/state/PKCE security validation, proof redaction and provider-rejection regression tests, targeted CI build, and [operator/approval runbook](docs/authentication/official-provider-poc-0261.md).
- **External gate unverified:** no developer app UUID, personal account or provider approval evidence was supplied; the real provider POC has **not** been executed. Official provider approval and live Java online-mode server entry remain required. Mocks only cover local regression testing.

## 0.26.0 — Textures & Personalization GA (release certification required)

- Finished the texture service milestones across 0.25.1–0.25.12: immutable PNG local/S3 storage, personal Desktop preview/library, Admin policy, signed Yggdrasil and strictly isolated official Minecraft integration.
- Hardened offline snapshot restoration against incomplete database inventory, oversized/symlinked manifests and failed readback after recovery; a partial snapshot can no longer report a complete restore.
- Maintenance `verify` now validates fully decoded canonical Minecraft skin/cape PNGs in addition to byte lengths and SHA-256 digests.
- Added an independently signed six-platform GA release verifier (actual Windows/Linux/macOS native builds, game rendering, owned Microsoft operations, PostgreSQL/S3 recovery, trusted OS installers) with adversarial tests and protected GitHub Actions release gate.
- Synced versions/OpenAPI and added [0.26.0 GA deployment and certification instructions](docs/releases/0.26.0-textures-personalization-ga.md).
- **Not certified by source tests alone:** external signed evidence and real client/platform execution are mandatory before publication.

## 0.25.11 — Texture Lifecycle & Recovery

- Transactional backup/restore inventory pins prevent garbage collection of in-flight snapshots.
- 45-minute fenced GC leases prevent stale workers from finalizing a later worker's cleanup.
- S3 GC verifies SHA-256 and uses signed conditional ETag-based delete.
- Local object repair publishes complete verified bytes with atomic replacement.
- Operator integrity verification with JSON reports and real PostgreSQL integration coverage.

## 0.25.10 — Gravit TextureProvider Migration

- Added an operator-only, executable TextureProvider importer reading upstream PostgreSQL `textures` records or a JSON export, and resolving local/S3 source objects without fetching legacy HTTP URLs.
- Added strict UUID ownership mapping with explicit override file, SHA-1/SHA-256 verification of raw PNG, full PNG decode/normalization, bounded reads, source-key validation and row-by-row quarantine reports.
- Connected imports to the existing per-user quotas, cape entitlements, staging, immutable local/S3 storage, saved gallery and transactional CAS assignment history.
- Added migration `0073` with atomic, idempotent import receipts and the `gravit-import` revision event; added tests and a targeted CI gate.
- See [Gravit TextureProvider migration guide](docs/textures/gravit-textureprovider-migration-02510.md). **Release gates:** production DB, S3/MinIO and live Minecraft verification remain required.

## 0.25.9 — Admin Texture Management

- Added a working Admin **Скины и плащи** workspace for global/project-scoped skin and cape policies, individual allow/deny/inherit exceptions, quotas, public default/fallback PNGs and their classic/slim models.
- Added transactional PostgreSQL policy CAS, immutable policy and exception histories, and read-only player assignment audit; all administrative mutations require global `settings:manage` and recent MFA.
- Connected policy decisions to the existing upload, saved selection, public texture blob delivery and Yggdrasil/ServerBridge; explicit individual denial overrides a permissive global policy or legacy cape grant.
- Added separate default vs unavailable-selection fallback resolution and GC protection for pinned local/S3 objects, with verified/public digest validation, new migration `0072`, OpenAPI updates, Admin UI tests and PostgreSQL integration test scenarios.
- See [Admin texture management and release checks](docs/textures/admin-textures-0259.md). **Certification:** full backend and Admin builds, PostgreSQL integration and live Minecraft tests remain mandatory release gates.

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

## 0.30.9 — Diagnostics & Sentry

- Opt-in Backend, Desktop (Tauri/JS) and JVM diagnostics with Sentry envelope ingestion, bounded error transport and sensitive-data minimization.
- Reproducible release upload path for JS source maps, Rust/native debug symbols and actual ProGuard mappings; reject mismatched or missing artifacts.
- Automated HTTP ingest/privacy tests and release artifact upload regression checks.

## 0.30.11 — Module Parity Completion and desktop startup optimization

- M01–M19 re-audited against 0.30.10 shipping implementations with module-specific executable evidence, while preserving the 0.30.1 immutable snapshot and the M17 security exception.
- Desktop optional screens split into lazy-loaded chunks with cancellable, bounded idle prewarming and a local loading boundary.
- Deterministic, verified SHA-256 prebuild index for Vite output, including no-shipping-source-map enforcement after Sentry uploader.
- Regression tests for current matrix trust boundaries, asset tampering, JS startup deferral, Discord, Sentry, DevTools and LAN discovery.

## 0.30.12 — Integration & Certification

- Fixed concurrent JVM-host forced-failure handling and preservation of the RPC/heartbeat root cause through process exit.
- Repaired Java SDK JAR version drift and Java E2E packaging; fixed Windows-compatible Java classpaths.
- Added real subprocess E2E runner for JVM/Gravit/trusted agents/DevTools/LAN/Discord/Sentry and updated M01–M19 evidence matrix, without inventing upstream parity certification.
- Added fail-closed Windows/macOS/Linux evidence review, CI JVM hang/crash regression and native Tauri production build gates.
- Local full Go supervisor, native desktop and live-service acceptance remain unverified pending CI.

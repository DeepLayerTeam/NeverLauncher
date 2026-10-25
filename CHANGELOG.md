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

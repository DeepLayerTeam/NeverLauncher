# Changelog

## 0.41.10 — Crash-safe world backup, restore, and JVM launch fencing

- **Atomic host maintenance gate (executing code):** world-backup create now owns a server-root-scoped exclusive gate before it checks the Host Supervisor, stops the real JVM, and copies the stopped world and plugin/user data. Every JVM spawn and crash-loop restart contends for this same gate; a concurrent start cannot race a confirmed-stopped snapshot. The gate uses atomic directory creation across CLI processes, not a voluntary status flag.
- **Fail-closed recovery:** interrupted backup/start processes leave a gate that blocks JVM starts and new backups. The new explicit `world-backup gate-recover --confirm stale-gate` checks the old owner's exact OS process identity, the supervisor PID, JVM process and host lock before removal. Incomplete or ambiguous metadata is never silently cleared. No backup or restore operation automatically restarts the server.
- **Verified restore:** existing SHA-256 payload validation, append-only backup identifiers, private storage, isolated no-overwrite destination, fsync and atomic publication continue to apply. Restoration reproduces actual world, playerdata, region and plugin bytes and refuses a second restore into an existing directory; no unsafe automatic in-place overlay is performed.
- **Real process tests:** build the actual `nl` CLI and exercise OpenJDK 21 JVM start, graceful stop, persisted binary world/UUID/plugin data, verify, isolated restore, replay rejection and absence of a second JVM launch (`scripts/test/world-backup-real-java-04110.py`). Unit tests exercise competing gates, ambiguous/crashed gate ownership and explicit recovery while offline.
- **Live Paper E2E correction (requires Docker + actual Paper):** fixed the `confirmed-stopped` assertion and extended the disposable Paper E2E to corrupt a stopped player's data deliberately, apply the recovered bytes back to its test volume, check every source file digest, and require the restored server to become healthy. This live Paper E2E cannot run without the actual Paper container, a joined player and Docker; it is not claimed as passed in the development environment.

## 0.41.9 — Live JVM/host telemetry and fail-closed freshness

- **Real runtime sampling:** signed ServerBridge heartbeat now carries the actual Java PID, process CPU time/load and OS-reported free/total host memory, when supported. Unsupported host fields are omitted (never replaced with fabricated zero values). Game-specific stale/future samples cannot report healthy ticks.
- **Cross-boundary validation:** Backend validates process ID against signed runtime identity, CPU limits and physically possible host memory values; accepted data is persisted alongside existing metrics in PostgreSQL.
- **Live view fails closed:** Backend masks stored samples whenever heartbeat, sample timestamp, runtime epoch, PID or active node state no longer match. Historical data stays in PostgreSQL, live overview reports `fresh`, `stale` or `unknown` and does not return stale numbers.
- **Admin:** shows JVM PID/process CPU load and real host free/total memory only for fresh samples; older overview no longer displays raw historical telemetry as live.
- **Tests:** Java 21 process-sampling and freshness tests, Backend process/freshness regression cases, Admin regressions. Upstream Minecraft JAR, PostgreSQL E2E and full Go 1.27.3 certification must still be run in a matching CI environment.

## 0.41.8 — End-to-end session-bound revocation and authorization fencing

- **Real revocation disconnect path:** PostgreSQL now places the revoked `sessionCorrelationId` into the durable, signed `player.kick` operation. Velocity, BungeeCord/Waterfall, Bukkit/Paper/Purpur/Spigot/Folia, Fabric/Quilt/Forge/NeoForge, and Sponge compare the queued correlation against their locally authenticated current session before disconnecting. A delayed operation for a previous login cannot kick the new session merely because the player name was reused. Folia checks again inside the scheduled entity action. Vanilla RCON sidecar refuses session-targeted kick since it cannot prove the active player's session.
- **Session checks at transfer redemption:** the PostgreSQL handoff read and atomic consume now require the owning NeverLauncher authorization session still to be active, unexpired, and bound to the original epoch. V3 handoffs reject fallback to legacy transfer semantics when runtime-bound session proof is absent; existing correlated player-session transfer fencing is retained.
- **Operator domain checks:** the existing `game:moderate` permission enforcement, project scoping and signed control channel remain mandatory. Session-specific moderation payloads must include a valid 64-character lowercase hexadecimal correlation ID. Game, host and backend control permissions remain separate.
- **Tests:** Java 21 tests cover 12 session replacement/revocation conditions and existing 20 authentication plus 19 control-journal checks. Targeted production common runtime, proxy runtime and Vanilla sidecar compilation completed. Full Go 1.27.3 test suite, real PostgreSQL failover, and upstream Minecraft/proxy integration still require CI/live verification; do not claim otherwise.


## 0.41.7 — Live Velocity/BungeeCord/Waterfall routing and verified transfers

- **Real proxy transfer path:** Velocity now gates the actually selected pre-connect destination against the current registered server and a one-time Backend handoff; BungeeCord/Waterfall use native `ProxiedPlayer.connect` after asynchronous Backend authorization. A failed/denied transfer does not disconnect an already connected player.
- **Post-connection evidence:** `proxy.connect` and `proxy.switch` are emitted only after the real platform `ServerConnectedEvent`, never merely because an authorization or handoff POST returned success.
- **Concurrent safety and topology:** per-player handoff fencing prevents parallel requests; stale async completions cannot clear a newer reservation. Registered target replacement, maintenance/drain, missing routes, capacity exhaustion or stale heartbeat fail closed, and there is no transparent retry for uncertain one-time transfers.
- **Actual Backend route validation:** replace unsafe JSON substring matching with the existing bounded strict parser and validate source ID, target identity, runtime epoch/revision/digest, health, route state, available slots and timestamps. The Backend still atomically re-checks routing and issues the one-time ticket in PostgreSQL.
- **Join-capable adapters:** include Quilt and Sponge in Backend route enumeration and topology alongside the existing supported server kinds. Vanilla RCON sidecar remains non-routable because it cannot enforce target-side handoff admission.
- **Verification:** OpenJDK 21 compiled the shipping common/Proxy runtime code and passed 83 existing/new Java assertions (including 19 new route checks). Canonical version metadata validation passed. Upstream proxy JAR build, live player migration and Go tests remain unverified in this environment (`go.mod` needs Go >=1.27.3). See `docs/servers/serverbridge-proxy-routing-0417.md`.

## 0.41.6 — Verifiable Fabric/Quilt/Forge/NeoForge/Vanilla/Sponge control effects

- **Four native modloader command paths:** existing real Minecraft command dispatchers now read back whitelist entries, whitelist enablement, and player ban state through supported platform methods when available. An unavailable API never fabricates `succeeded`; a mismatched postcondition fails. Native logout callbacks correlate requested kicks to the same player UUID before returning evidence to Backend.
- **Vanilla RCON sidecar:** state-changing whitelist and ban commands issue a second read-only RCON list query and verify exact membership only with an unambiguous, complete response. Explicitly rejected RCON commands fail; queued shutdown remains `accepted`. Local TCP authentication/packet-fragmentation integration checked.
- **Sponge:** tracked native quit confirmation, no blind `succeeded` after queued stop, partial-broadcast errors remain indeterminate, and whitelist mode is verified only after a readable state check; unsupported Sponge API operations continue to fail closed.
- **Executable Java 21 verification:** compilation of bridge-common + Vanilla sidecar; 28 postcondition, kick and RCON parser assertions; actual localhost TCP RCON authentication/fragmentation exchange. The existing Bukkit-family 117-regression suite also passes.
- **Verification boundary:** Gradle API artifacts and genuine modloader, Vanilla and Sponge Minecraft server JARs were not available in the isolated environment. Their live compatibility and full Backend/PostgreSQL E2E are not claimed as passed; see `docs/servers/serverbridge-modloaders-0416.md`.

## 0.41.5 — Executable Bukkit-family control and observed command outcomes

- **Live platform handlers:** update the shared Bukkit-family production plugin used by Spigot, Paper, Purpur, and Folia. Whitelist enable/disable/add/remove and name bans/pardons now report `succeeded` only when actual platform readback matches the requested state. A command dispatcher returning `true` without changing the platform is `indeterminate`, not a verified success.
- **Observed player kick:** register a player UUID-specific completion waiter *before* invoking `kickPlayer`, and correlate a `PlayerQuitEvent` emitted by the game server to the original command. Folia executes the kick via the player's EntityScheduler; other Bukkit-family implementations use the main server scheduler. An absent quit, retired player, plugin shutdown or scheduling failure cannot be promoted to verified success. Timeout and duplicate concurrent kicks do not create an additional physical kick.
- **Backend verification:** validate `player-quit-event` evidence (`username`, `uuid`, `online=false`) and `platform-state-read` for `ban.add/remove` against the original signed, persisted command. Preserve `executed` for console, broadcast and world-save dispatch: these APIs do not prove delivery to every recipient or durable on-disk persistence.
- **Folia partial failures:** broadcast using per-player EntityScheduler; count each retirement/rejection or failed send once and return `indeterminate` on partial completion, never unconditional success. Server shutdown is queued without blocking the shared heartbeat I/O executor and remains `accepted` until the separate host lifecycle provides genuine process confirmation.
- **Offline regression:** `python3 e2e/scripts/test-bukkit-control-0415.py` compiles the *shipping Java plugin source* against a deterministic Bukkit API simulator and exercises all four platform adapters, readback mismatches, control permissions, Folia entity retirement, delayed ACK semantics, duplicate kicks and plugin teardown (117 checks locally).

**Verification boundary:** Java 21 offline command-path checks passed. No genuine Spigot/Paper/Purpur/Folia distribution JARs were available for executable live-server tests; the real game server integration, upstream API dependency build, full Go 1.27.3 Backend tests and cross-runtime PostgreSQL ACK E2E remain **unverified**. This change is production-path source code, not independently certified production release packages. Do not represent `executed` as verified effects.

## 0.41.4 — Verified real JVM lifecycle, supervised shutdown and crash recovery

- **Real JVM startup evidence:** `nl server-bridge host start` no longer returns an optimistic `starting` acknowledgment after four seconds. It waits for the exact supervisor PID, OS-verified child PID and matching process identities; a failed, crashed, prematurely exited or unverified JVM is not reported as running. A 30-second timeout is an *unverified outcome*, not permission to retry blindly.
- **Graceful service termination:** the real Host Supervisor captures SIGTERM/SIGINT and forwards the Minecraft `stop` command to its verified Java child's stdin. It waits for exit and escalates only to identity-checked OS termination/kill after the configured grace period. Capturing the signal also prevents an immediate supervisor exit leaving an orphaned JVM.
- **Crash/restart stop race closed:** `host stop` now targets the active supervisor session while a crash-restarting JVM has no live PID. A PID-zero session-bound stop remains valid if the JVM is spawned concurrently; stale sessions cannot terminate a new supervisor. The restart backoff handles OS shutdown signals as well, preventing unwanted Java launches after service stop.
- **Fail closed on process identity:** a JVM whose identity cannot be verified after spawning is terminated rather than being exposed as managed or verified. PID reuse and orphan protection remain enforced; automatic adoption of a JVM that outlived its supervisor is deliberately forbidden.
- **Real Java 21 regression tests:** compile a runnable Java JAR using javac/jar and exercise real OS Java processes, stdout, in-game save marker, stop/restart with new supervisor session and process identity, SIGTERM, crash-once recovery, capped 3-attempt crash-loop, cancellation during restart backoff, and a built production CLI's actual `start/restart/stop` commands. No shell-based fake-Java executables in these scenarios.
- **Verification boundary:** the host lifecycle and production CLI live-Java tests pass on Linux/OpenJDK 21. This is not full Minecraft plugin/Proxy certification, Windows/macOS runtime certification, PostgreSQL/Backend integration certification or a claim that the entire monorepo has passed its CI.

## 0.41.3 — Backend ↔ RemoteControl ↔ Host Supervisor: durable real-host operations

- Backend now executes real JVM lifecycle actions (`start`, `stop`, `restart`) against explicitly provisioned RemoteControl agents via pinned TLS 1.3, bearer capabilities and optional client certificates. Project-scoped game permissions cannot authorize host actions; a global `host:process` permission and fresh MFA are required.
- Each action first commits an immutable PostgreSQL operation ID, original user/idempotency key, remote node identity, host pre-state and ServerBridge runtime baseline. A duplicate request returns the same operation without re-execution. An uncertain operation blocks new keys on that node until manual reconciliation; no backend crash or lost ACK causes automatic physical replay.
- RemoteControl dispatches to the existing real Host Supervisor and now polls OS-verified process state before storing a `succeeded` receipt. Start requires a live JVM and supervisor, stop requires both to be gone, and restart requires a new supervisor session; timeout or unverified state remains `indeterminate`.
- Backend correlates host receipts, observed JVM/Supervisor state, and a fresh ServerBridge heartbeat for the new runtime. If the process is running but the game agent has not reconnected, the operation stays `accepted`; GET with `refresh=1` performs read-only reconciliation. The Backend never converts an uncertain remote result to success based on PID alone.
- Registry of operator-approved hosts in `NEVERLAUNCHER_SERVER_BRIDGE_HOST_TARGETS_FILE`. No user-supplied URL, shell commands, JVM arguments or filesystem paths are accepted by the operation API. Database migration 0111 provides durable idempotency, final receipt fencing and per-node uncertain-operation serialization (mirrored to CLI migrations).

**Verification:** local stdlib-only TLS RemoteControl client tests pass. Full Go 1.27.3 Backend/CLI suite, live PostgreSQL migrations, Minecraft game-agent reconciliation and multi-host E2E have not been run in this environment. Do not claim external production certification until these pass.

## 0.41.2 — Durable ServerBridge command journal, ACK replay and no-redelivery after lease expiry

- **Live agent execution:** ServerBridge now acquires an exclusive per-journal OS file lock before enabling control. Starting a second JVM/plugin instance against the same identity journal fails closed; a plugin reloaded while its former executor remains active retains the lock until process exit. An execution marker is atomically persisted and fsynced **before** invoking the platform. An interrupted `executing` record can be acknowledged as `indeterminate` and is never invoked a second time.
- **Durable receipt outbox:** Record the original command ID, runtime, channel, delivery sequence and lease token with its completed result. On each control poll, retry unapplied ACKs before accepting new work. Persist the ACK confirmation together with the channel watermark; losing a Backend response now resends the same proof, **not** the game action. Legacy 0.41.1 journal entries remain readable and immutable.
- **Safe journal retention:** No compaction deletes execution tombstones. Journal rewrites have SHA-256 integrity seals, unique temporary files, file fsync, atomic rename and POSIX parent-directory fsync; corruption or an unavailable exclusive lock prevents the control agent from starting. Owner-only permissions remain in place on supporting filesystems.
- **Backend lease recovery:** Both PostgreSQL and in-memory implementations accept a *late durable receipt* only for the original command ID/runtime/channel/token/sequence and only when the pending `indeterminate` was synthesized from an expired/superseded lease. Genuine agent-reported `indeterminate` results and conflicting ACKs remain immutable. The expired lease is never reassigned and command attempts do not increase.
- **Conservative handler exceptions:** If a platform handler throws or returns no result after durable admission, the agent records `indeterminate` instead of incorrectly asserting that no side effect took place.
- Runnable Java 21 tests exercise crash markers, journal locks, ACK-loss recovery, tamper rejection, digest conflict, retention beyond the former compaction threshold and JVM-runtime change. Go regression cases cover late ACK, mismatched tokens, immutable agent uncertainty and no-redelivery.

**Verification boundary:** Java 21 compilation and local WAL regression tests passed. Go 1.27.3 is required by `services/api/go.mod`, but only Go 1.23.2 is available in this execution environment; the Go tests and live PostgreSQL/Minecraft HA fault-injection certification remain unexecuted. During a full JVM restart, the old runtime's command may remain `indeterminate` by design; it is not re-executed and is not falsely claimed to have succeeded. Deploy without running mixed old/new agents against the same journal.


## 0.41.1 — Distinguish accepted, executed and platform-verified ServerBridge results

- The live Bridge executor records `accepted` for scheduled shutdown and `executed` for completed handler/dispatcher calls without an observable effect. `succeeded` now requires an observed platform postcondition and an explicit `platform-state-read` receipt. Bukkit maintenance/drain and whitelist changes read state back after invoking the action.
- Backend classifies every signed ACK against the original persisted command and downgrades legacy/unproven `succeeded` receipts rather than presenting optimistic ACKs as proven success. A `server.shutdown` receipt never becomes a verified stop based on scheduling alone.
- PostgreSQL accepts the new terminal outcomes and retains the same immutable command, lease, acknowledgement replay and no-redelivery fencing. Admin distinguishes acceptance, invocation, agent-verified result and unknown outcome.
- New regression tests cover verifier claim matching, legacy agents, shutdown receipts, terminal replay and UI states.

**Verification boundary:** `succeeded` represents a postcondition checked by the enrolled game agent, not independent remote attestation from Backend. Cross-runtime live Minecraft certification, abrupt agent/backend fault testing and full package verification are still required before declaring 0.41.1 production-certified.


## 0.41.0 — Final package update-integrity gate and delegated delivery signatures

- Close the gap between a signed, apparently valid desktop installer and a usable installed client: the existing six-target production rehearsal now verifies the **exact embedded `COMPONENT_UPDATE_MANIFEST.json`** against its shipped executables, runtime, guard, updater, package manifest and (on Windows) sensor. Validate the installed source paths, component roles, expected layout, SHA-256, byte sizes, and version/platform/architecture. Reject altered, absent, misrouted, or untracked update components before publishing.
- Generate and package the **delegated Ed25519 component signature and root-signed trust policy** in both the Linux TAR and macOS app Resources, bringing these packagers in line with the existing Windows updater-signing path. The release verifier validates the historical and delegated signatures cryptographically, using externally configured public trust roots; a signature digest assertion alone is insufficient.
- Keep independent final-package GA approvals, compatibility results and final publication dry-run mandatory. Extend the existing release CI job with executable Linux/Windows/macOS package-writer tests, signature verification with isolated ephemeral keys, and rejection tests for forged signatures, missing policy, unsafe paths and changed component bytes.
- Synchronize all versioned package, OpenAPI and target-matrix metadata to 0.41.0; preserve existing 0.36.x signing and rehearsal behavior without migration of historical test receipts.

**Verification boundary:** Local signed-package fixture tests, existing release gate regression tests, version alignment and target-schema validation pass. Genuine Windows Authenticode/macOS notarization, Rust Desktop/NeverRuntime builds, all 280 required game combinations, and complete player install → launch → update → repair → rollback against final packages could not be executed on this Linux sandbox. This patch is **not a completed production GA certification** and must not be published as such without fresh live results. In particular, final macOS code-signing may change the app executable after embedded update manifests are sealed: the release verifier deliberately blocks any resulting mismatch rather than silently accepting an updater-unusable package.

## 0.40.10 — Bind cross-platform compatibility results to delivered evidence

- In the real per-target Minecraft compatibility execution path, record a SHA-256 digest for every uploaded installer, materialized client verification, Java/runtime certification, and actual-client launch report. Bind that list to the target, commit, run and platform as part of the final compatibility result.
- The release matrix aggregator now opens the uploaded artifacts and checks their exact bytes against the runner-issued hashes, instead of accepting a list of filenames and asserted PASS flags. Missing, duplicated, replaced, symlinked, oversized and modified evidence fails certification. Preserve explicit unsupported status for the twelve upstream-unavailable targets.
- Keep the existing genuine game and loader certification scripts in place (Vanilla/Fabric/Quilt/Forge/NeoForge, Windows/Linux/macOS x64/ARM64), including native/processor and matching-server checks. The new validation applies uniformly to all required targets without narrowing the matrix.
- Update product and packaged Desktop/Tauri versions together to avoid shipping an installer that reports a stale version.
- Add regression checks demonstrating that a passing matrix becomes a failed release when a previously uploaded client package or Forge installer result is deleted or modified; reject symlinks pointing outside the downloaded artifact set.

**Verification boundary:** These are executable changes to the CI runner and release verification, not simulated Minecraft PASS results. The available host cannot complete all 280 genuine target runs (including six platform/architecture combinations and five major Java versions). No required target is reported as certified by this patch. Full GA acceptance remains blocked until fresh real Minecraft execution and uploaded artifact validation passes on the claimed platforms.

## 0.40.9 — Preserve crash-recoverable rollback across client repair

- Repair of the **same signed release and component selection** no longer replaces the last-known-good checkpoint with a backup of potentially damaged pre-repair bytes. Keep the earlier verified A → B backup and advance its active release identity after a successful B → repaired B transaction.
- Apply the same checkpoint-preservation rule during crash recovery when the repaired files and active pointer were already published but journal finalization was interrupted. A second repair retains the same earlier verified rollback target.
- On a first-time installation or repair without a genuine predecessor, do not publish a fictitious rollback target that would remove a working client. Explicit rollback requires a previously installed release and still checks signed contents, backup integrity, anti-rollback policy and active release identity.
- Add regression tests for update → corruption → repair → rollback, crash recovery between pointer and final journal, and first-install rollback refusal. Verify that unmanaged mods and world saves remain untouched.

**Verification boundary:** This is an executable NeverRuntime transaction-path source change. The local environment has no Rust toolchain and cannot fetch it, so compilation, automated Rust test execution and actual Minecraft/Desktop kill-and-restart acceptance remain unverified. This source patch is not a certified production GA release until those tests pass.

## 0.40.8 — Verified resumable HTTP delivery, bounded ranges and cross-mirror repair

- Extend the production NeverRuntime file downloader to consume valid **bounded HTTP 206 ranges** until a signed file is complete. Keep its strong `ETag` and `If-Range` validator across suffix requests without discarding already downloaded bytes or using one scheduler retry per healthy bounded response. Bound range chaining to avoid infinite/abusive server responses.
- Preserve an interrupted partial while switching between signed download mirrors, using `Range` without forwarding another origin's `If-Range` ETag. Every assembled file is still authenticated against its **signed full SHA-256** before installation; incomplete or corrupt files never replace a working client.
- Atomically update persistent partial metadata to the new mirror identity/ETag before writing cross-mirror bytes, including Windows replacement semantics. A subsequent Desktop restart resumes using the new origin's ETag, not the previous origin's validator.
- If a resumed file fails final SHA-256, discard its partial and trigger the existing bounded retry mechanism for a clean full fetch from the same source. A corrupted local prefix therefore does not require manually reinstalling the game.
- Add local HTTP fault-injection tests for truncated bodies, short but valid 206 responses, cross-mirror suffix reuse, interrupted mirror resume after a restart and corrupted-prefix recovery with the prior client left intact.

**Verification boundary:** The Rust source and executable tests are included, but Cargo/rustc are unavailable in this execution environment, so the Rust test suite, Desktop builds and real network-fault Minecraft installation have not been executed here. This version is not production-acceptance certified until those tests and a real Desktop install/update/recovery pass.

## 0.40.7 — Verified JVM execution, offline repair and clean-host Java selection

- Verify managed runtimes by **executing real Java-8-compatible bytecode** with a random challenge, checking its runtime major and ensuring `java.home` belongs to the installed image. Reject wrapper scripts that merely forge `java -version` output or delegate to the machine's unrelated Java.
- Repair damaged Temurin installations from the previously SHA-256-verified local archive, including with network access disabled. Preserve the exact original release and archive checksum; do not silently switch to the host Java or an unknown vendor build.
- After acquiring the inter-process installation lock, reclaim abandoned extraction directories from previous process crashes, without following symlinks. Give quarantined archives and runtimes collision-resistant names for consecutive repairs.
- In Desktop, install/verify the **signed profile's managed runtime even when a compatible system Java exists**. Never save an automatically resolved Java path as a global custom override: profile changes must select and repair their own runtime.
- Add a reproducible Java-8 bytecode probe, native JVM tests, damaged/stub runtime rejection and a Linux/macOS clean-host acceptance script using a real pinned JRE/JDK archive (including an interrupted-install repair).

**Verification boundary:** The bundled Java bytecode executes on the available Java 21 host, and the shell acceptance script passes syntax checks. Rust/Tauri builds, a real fresh Temurin download/installation and Minecraft launch have not been certified in this environment, which lacks Cargo/rustc and access to a pinned official runtime archive. The release must not be represented as end-to-end production-accepted until those executions pass.

## 0.40.6 — Executable legacy Forge inheritance, classpath precedence and Java launch

- Correct the legacy `minecraftArguments` inheritance for Minecraft 1.7.10/1.12.2 and classic Forge LaunchWrapper. A Forge child profile that contains an identity placeholder no longer discards base `--gameDir`, `--version`, asset or access-token arguments. Child flags override only corresponding parent flags, preserving quoted argument boundaries.
- Apply the same inherited-argument logic in **both** the Go Client Factory legacy-run path and the Rust NeverRuntime compatibility resolver, avoiding different game invocations for the same installed legacy profile.
- In NeverRuntime, put applicable Forge child Maven libraries before inherited Minecraft libraries and honor child version overrides while retaining platform filtering. This matches the Client Factory's verified classpath and prevents the wrong version of a class loading from the parent.
- Use the linked CLI build version in the legacy launcher variable instead of a hardcoded, outdated version string. Make the already-implemented legacy inspect/run operations discoverable in CLI help.
- Add negative argument-inheritance tests and a JVM integration that compiles Java-8-compatible bytecode, runs a controlled LaunchWrapper entrypoint and verifies actual classpath override, identity/game flags and refusal to execute a modified JAR. The fixture tests **do not** execute authentic Forge, Mojang Minecraft or Java 8: the local Java 21 host runs bytecode compiled with `--release 8` via a version-probe shim. Java 8 runtime checking remains mandatory in production.

**Verification boundary:** Go legacy tests and CLI build pass on the available Linux host. The real Minecraft 1.7.10/1.12.2 and official legacy Forge game launches, Java 8 runtime, Rust Desktop build, and Windows/macOS target runs are not certified by these tests; `0.40.6` must not be described as a completed production GA release until they pass.

## 0.40.5 — Executable MirrorHelper workspace, modpacks, libraries and authlib

- Extend the real `client-factory apply-workspace` transaction to install an exact `.mrpack`/CurseForge pack, resolve and hash its files, apply verified additional mods, download pinned Maven JARs and register them in the effective Minecraft version profile. No manual staging of factory outputs or post-build classpath editing is required.
- Compare archive Minecraft/loader/loader-version pins against the workspace before performing network installs. Preserve the importer's source hash, optional-file, missing-artifact and redistribution-permission rules; on failure, keep the final client directory absent.
- Apply optional pinned authlib class overlays (base, patch and resulting JAR SHA-256), and optional verified classloader/javaagent compatibility requests in the same unpublished workspace. A custom Yggdrasil agent remains disabled until `--allow-auth-agent true` is supplied explicitly.
- Resolve local archive, compatibility request, patch, mod and library files relative to the workspace JSON; support clean installation in nested output directories and explicit `--target` platform selection. Reuse existing transaction lock, stage/verify steps and source/action receipts.
- Allow CurseForge packs composed solely of embedded override files to install without an API key; upstream CurseForge file records still require exact authenticated metadata.
- Add HTTP-backed full-workspace tests that import a Modrinth pack, install and register a Maven dependency, apply auth mode, verify file hashes, reject mismatching game pins and wrong mod hashes, and verify authlib patching/tamper detection. Also run an installed Maven JAR entrypoint with a real local JVM.

**Verification boundary:** The workspace and existing MirrorHelper/Modpack/compatibility Go integration suites execute with local fixtures and the Go CLI builds. These checks do not represent a genuine third-party Modrinth/CurseForge service integration, an authentic Minecraft launch or cross-platform Rust Desktop certification. The acceptance goal remains open pending such tests.

## 0.40.4 — Forge/NeoForge target-specific libraries and executable processor checks

- Apply Vanilla OS and architecture selection to both Forge/NeoForge installer libraries and inherited runtime libraries, honoring `allow/disallow`, `clientreq=false` and native classifier architecture. Keep unselected entries in the version profile for runtime rule evaluation; do not fetch their artifacts on incompatible systems.
- Reject Forge/NeoForge Maven artifacts whose declared path does not match the dependency's canonical Maven coordinate, before loading a local JAR or requesting a repository object. Preserve installer-embedded and processor-generated files at their verified identities.
- Run a local HTTP integration with **real Java 21**: execute Forge and NeoForge processor JARs through the isolated processor worker, read installer patch bytes, create output JARs checked against installer output SHA-1 and load the resulting Java entrypoint with the JVM. The base Minecraft and bootstrap main class are controlled test fixtures.
- Retain existing installer identity checks, resolution locks, crash-recovery journals and Client Factory packaging; tests also exercise wrong-platform dependency exclusion and malicious Maven-path substitution.

**Verification boundary:** Forge/NeoForge Go tests (including the JVM processor integration) and Go CLI build pass in this environment. This test demonstrates executable processor and classpath behavior with fixture data, **not** a successful authentic Forge/NeoForge launch inside the Mojang Minecraft client. Desktop/NeverRuntime Rust and all required native target combinations remain unverified; do not label this version GA-certified without their real-world results.

## 0.40.3 — Fabric/Quilt platform-aware dependency delivery and JVM classpath

- Materialize only Fabric/Quilt libraries required by the selected target OS/architecture; honor Mojang allow/disallow rules, native architecture suffixes and `clientreq=false` so an unavailable Windows or server-only artifact cannot block a Linux client. Preserve the original conditional metadata for runtime resolution on the selected platform.
- Enforce an exact canonical Maven relationship between each applicable library coordinate and its `downloads.artifact.path`. Reject path drift before download and keep strict SHA-1 checks over the actual downloaded JARs. Accept explicit `@jar` coordinates but reject unsupported non-JAR classpath extensions and unsafe Maven segments.
- Preserve verified SHA-1, size, URL and target scope for installed loader libraries in the generated inherited version profile, allowing NeverRuntime to build the correct runtime classpath.
- Exercise **real JVM entrypoints**, compiled fixture JARs, transitive Java class loading, Fabric/Quilt profile materialization and a local HTTP Maven repository, including OS-excluded and server-only dependency cases. These tests verify executable classpath delivery, not a Mojang Minecraft gameplay session.

**Verification boundary:** Targeted Go CLI integration tests, the CLI build, and local Java-21 fixture entrypoints pass on Linux. The full CLI test run reports failures in component parity, release doctor, module parity, and version-pinned BOM tests; it is not green. No authentic Mojang Minecraft client or Fabric/Quilt upstream loader was started. The Rust Desktop/NeverRuntime build and multi-OS certification remain unverified here; do not mark this patch as release-certified.

## 0.40.2 — Vanilla materialization: native libraries and asset integrity

- Extract verified Vanilla native archives into isolated OS/architecture trees; publish any path shared by multiple identical native archives only once in the client package file list. Conflicting bytes are refused.
- Materialize macOS x64/ARM64 LWJGL native libraries from the official nested `macos/{x64,arm64}/org/lwjgl` or `osx/{x64,arm64}/org/lwjgl` archive layout into the `java.library.path` root. Do not substitute binaries for another architecture; reject collisions and symlinks.
- Verify SHA-1 and expected size over **the actual copied bytes** when generating legacy `resources` / virtual assets, before atomically replacing a destination. A source changed between initial validation and copy is rejected without modifying the last verified asset.
- Add local-HTTP end-to-end materializer tests for duplicate native archives and macOS ARM64 extraction, and negative tests for wrong-architecture, collisions, and tampered resources.
- Carry forward the existing production Vanilla version metadata, library/asset downloads, per-file checksums, and Client Factory → backend → Desktop delivery.

**Verification boundary:** Go CLI tests and build were run on Linux. The sandbox has no Mojang connectivity and no Rust toolchain; no authentic Minecraft client execution or six-target certification is claimed. This is an executable source patch, not a certified GA release.

## 0.40.1 — Client Factory → Build Workspace delivery

- Connect the existing CLI Client Factory, backend Build Workspace persistence, and Admin workflow through a direct server-side transfer of **verified executable client files**. No browser-side ZIP extraction or re-upload is required.
- Re-run the Client Factory CLI verifier for the completed job and compare its verified plan identity before transferring bytes.
- Reject path traversal, symlinks, changing file digests, per-file size violations, duplicate case-insensitive paths, unsupported file ownership, and source/loader/Java/profile mismatches.
- Encrypt files into existing private content-addressed Build Workspace storage; commit the whole workspace's file list only after every object has been read back and authenticated.
- Pin `runtime.launch.classpathStrategy = mojang` and the exact loader metadata path in the same revision-checked workspace commit. Preserve the existing immutable settings rule for ordinary workspace operations.
- Allow the operator to continue through existing Stage → Validate → Build → Sign → Staged Run → Publish, where Desktop and NeverRuntime consume signed, SHA-256-verified releases.
- Add focused negative tests for the transfer paths, profile identity and repository transitions.

**Verification boundary:** Existing CLI materializer tests pass in the local Linux environment. The API test suite cannot run here because the repository requires Go 1.27.3 and its dependencies/toolchain are unavailable. The Desktop/Rust build and a real Minecraft game-to-server launch have not been executed in this environment. Consequently 0.40.1 is source-level implementation work, **not** a certified production/GA release.

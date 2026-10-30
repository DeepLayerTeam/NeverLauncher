# Changelog

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

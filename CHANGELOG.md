# Changelog

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

# Five native Java Gravit source-port behaviors — 0.49.5

This folder provides **executing source-code ports**, not a drop-in binary loader for any GravitLauncher JAR. It reuses the NeverLauncher Java Extension Host/SDK and the existing Go broker; it cannot directly mutate Go heap objects. The trusted game hook is an additional *fully trusted* Java agent running in the game's JVM, **not an extension sandbox**.

## Build and local JVM acceptance

```sh
sh examples/extensions/gravit-five-0495/build.sh test
```

The test creates real runnable Java Host JARs and a separate JVM agent plugin, starts a real Java subprocess, sends authenticated RPC/hook callbacks, exercises real PBKDF2-SHA256 verification and immutable UUID resolution, reconstructs an unsigned ZIP from digest-verified broker content, tests a pre-save profile veto, tests persisted JSON and state migration via a simulated broker, and launches a JVM with `-javaagent` to transform a synthetic `net.minecraft` class. Tampered plugin digest, changed library digest, cross-project reads, invalid credentials/hashes and unapproved loader changes must fail. The Python Host broker in this acceptance test is **simulated**; the Go source changes are not covered by this simulation.

## Deploying to a real installation

1. Back up the PostgreSQL/project and per-extension JSON state, import supported Gravit users and game content using existing 0.49.2–0.49.4 tools, then verify UUIDs, source hashes and migration dry-run.
2. Review `launcher-extension.json`. Build the Java JAR and package it with the existing NeverLauncher `extension pack` and trusted Ed25519 signing flow. Install it in a **separate project-scoped, trusted JVM** and grant `events:subscribe`, `events:sync`, `project:read`, `storage:read`, `storage:write`, `cli:contribute` explicitly. Restrict operating-system access because a Java extension with these permissions is not sandboxed from all host filesystem/network resources in the current runtime.
3. Configure the extension's existing broker `runtime.config` document `legacy-identities` as a JSON map by username, each entry containing `uuid` (canonical persistent Minecraft UUID), `name`, `scheme: "pbkdf2-sha256"`, `iterations` (210000–2000000), `saltHex` (16–64 bytes), `hashHex` (32 bytes). **Do not store plaintext passwords**. Only already supported PBKDF2 accounts work; unsupported Gravit hashes must be migrated via approved password reset or a separately reviewed provider. No legacy refresh token becomes a NeverLauncher session.
4. Configure `legacy-assets`: each `libraries/...`, `mods/...` or `optional/...` path maps to `{projectId,version,sha256,size}` of an existing file in the authenticated Go storage broker. Set `bundle:<projectId>` to an array of up to 24 exact paths. In pre-sign packaging the extension reads these files, verifies hash and size, and assembles a bounded unsigned ZIP. Publish it only through the normal release signing/policy pipeline; the Java provider alone never publishes a trusted package. Actual loader installation and Minecraft runtime setup remain owned by core from the previously migrated profile.
5. Activate the new Go `profile.before-save` synchronous subscription and verify updates/create are **rejected** when this hook vetoes or its subscribed Java Host is unavailable; successful operations still go through the existing Backend transaction/revision checks.
6. Register an approved, SHA-256-pinned `game-hook.jar` via the existing trusted JVM agent launch pipeline. The included hook changes exactly one fixed test class constant and is a **working demonstration**, not a universal Minecraft mapping or anti-cheat bypass. Replace it with a reviewed project-specific transformer and test it against the exact Minecraft/JDK/loader matrix before production use.
7. Test `ported-status`, `ported-save` and an update with a `0.49.4→0.49.5` `state.migrate` callback; the existing Go updater checkpoints extension-owned documents and rolls them back on failed updates. External DB/world changes are not included in this checkpoint.

## Scope and release blockers

The five local behaviors are executable and tested on OpenJDK 21, but **the target of five complex Gravit customizations on an independently accepted real PostgreSQL installation is not yet met**. A production release requires Go 1.27.3 compilation, actual PostgreSQL/Backend/Java Host install, RBAC/revocation tests, signed .nlext and agent packages, authentic source project inputs, Minecraft launch/join, update/restart/revoke/rollback of a real project, and independent evidence. The included JVM class fixture is not a real game client. This patch does not claim universal Gravit binary API/ABI compatibility.

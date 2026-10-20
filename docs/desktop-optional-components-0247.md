# NeverLauncher 0.24.7 — Desktop Optional Components UI

## Scope

Desktop lists visible signed components with search, categories and the signed hierarchy. Required/limited/hidden components cannot be enabled manually. The user can select a base preset and then enable/disable individual signed component IDs.

**The manifest/catalog/signature are never rewritten.** A deterministic client preference such as `@custom:v1:quality:+iris,-optifine` is persisted separately and is interpreted by the same Rust resolver used for SHA-256 downloads, installed ownership, recovery and launch. The format references only signed IDs. Unknown/duplicate/too-long IDs and edits to required or hidden/limited components are rejected. Dependency expansion, version checking, conditional availability and conflicts are still authoritative in native code.

Desktop calls the pinned Ed25519-verifying native preview, and compares the requested plan against the validated release ownership journal. The preview reports added/removed paths, plan digest and an **upper bound** on transfer bytes based on local SHA-256 checks; the content-addressed cache may reduce real network traffic. Files previously unknown to NeverLauncher cannot be claimed implicitly even if their contents have the expected hash.

The change is **not persisted before install**. On confirmation, Desktop runs real transactional download/commit using the exact preference, checks selected SHA-256 files and then asks Tauri to persist it only if it matches the installed signed release. Recovery of an interrupted durable job reloads the installed preference instead of assuming the old UI setting. A different launch preference is blocked by `ensure_active_preset` until installed.

## Testing

- `cd apps/desktop && npm run test:components`: canonical encoding, duplicate/unsafe inputs, incompatible component replacement and required protection.
- `cargo test -p neverruntime custom_selection_0247` (from Rust workspace): signed v5 catalog selection and transitive dependency resolution, invalid unsigned IDs, duplicate operations, forbidden required removal, incompatible exclusivity.
- Full Desktop: `cd apps/desktop && npm ci && npm run build`; Tauri: `npm run tauri:build` (requires system toolchain and platform dependencies).
- Manual E2E: install `minimal`; enable a component requiring a hidden dependency; confirm local size estimate; install and launch; restart Desktop and verify persisted choice; change to incompatible preset and verify confirmation/removal; interrupt/resume download and verify journal; attempt a collision with an unmanaged file and verify refusal; corrupt an owned JAR and repair; try missing entitlement and required component removal.

## Constraints

Component conditions with server permissions remain fail-closed until authenticated server entitlement evidence is implemented (prior O04 limitation). TypeScript standalone unit tests can pass without running a real Rust or Minecraft E2E; those external checks remain required for production deployment. This release does not introduce a new unsigned action/JVM argument entry point.

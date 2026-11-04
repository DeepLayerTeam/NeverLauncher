# Component selection persistence and migration (0.24.10)

## Usage

1. Install a signed component selection in **Desktop → Profile and components**. The chosen preset/overrides are written to DesktopConfig only **after** Runtime commits and verifies the resolved download plan.
2. Load a later signed manifest of the same project, profile and channel. Desktop does **not** discard an old preset just because it was removed from the catalog. Open **Profile and components → Transfer and selection backup**. A native migration preview reads the verified installed release pointer, expands the old selected component IDs, and resolves them against the new signed catalog.
3. Review preserved IDs, disappeared IDs, added dependencies, changed preset, managed-file removal and maximum download size. Explicitly confirm the proposed configuration. The existing transactional downloader verifies SHA-256 and managed ownership, and settings are saved only after successful installation.
4. Use **Export installed selection to JSON** to save a selection profile. The generated JSON remains visible in Desktop if the platform's file download handler is unavailable. Use **Import from JSON file** or paste JSON to preview, then confirm installation.
5. **Rollback to last-known-good** restores the verified previous release and its original component selection. Desktop reloads its signed manifest and updates DesktopConfig only after validating the active pointer and selected files. Published releases with positive `gameReleaseGeneration` still require a newly authorized generation to roll back.

## Portable selection JSON

`schemaVersion: "1.0"`, `projectId`, `profileId`, `channel`, `sourceVersion`, `sourceCatalogDigest`, `sourcePreset`, and `selectedIds` (stable signed component IDs). Source version/digest are informational, **not proof** that an imported selection was signed: import is an untrusted user preference. It contains no URLs, paths, JVM arguments, executable actions or authentication material. Import rejects unknown fields, duplicate IDs, malformed names, files larger than 1 MiB, and cross-profile/channel imports. Runtime verifies the **target** manifest with the pinned Ed25519 key before resolving any imported ID.

New dependencies and mandatory components are resolved by the same native resolver as installation; incompatible conditions or signed conflicts return blockers and cannot be installed. Missing old components are reported and do not authorize deletion of user-owned files. No operation directly modifies `.minecraft` outside the existing signed managed-ownership transaction.

## Implementation and verification

- `runtime/runtime/src/component_selection_02410.rs`: strict portable JSON, migration, signed-ID reconciliation, native tests.
- `runtime/runtime/src/transactional_release.rs`: verified active selection extraction under release lock, reuses existing journal recovery and installed-byte verification.
- `apps/desktop/src-tauri/src/main.rs`: native export/import/migration and active snapshot commands; Ed25519 trust boundary.
- `apps/desktop/src/ComponentPortability02410.tsx`: file import/export, proposed selection, resolved diff, explicit confirmation.
- `apps/desktop/src/main.tsx`: preserves previous preference across manifest refreshes, synchronizes DesktopConfig after rollback.

Run `cargo test --manifest-path runtime/runtime/Cargo.toml component_selection_02410` and `npm --prefix apps/desktop run build` with the project dependencies installed. Full Minecraft integration should exercise `old selection → new signed release → migrate → install → launch → rollback`, including simulated failure and user-owned file collisions.

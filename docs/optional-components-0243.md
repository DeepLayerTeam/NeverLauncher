# NeverLauncher 0.24.3 — Signed dependency / conflict resolution

## Production behavior

Component catalog schema `3.0` is embedded in an Ed25519-signed Manifest v3 snapshot. The snapshot has an incremented `revision` and `digest`. The digest covers all topology fields from 0.24.2 plus component versions, ordered dependencies, ordered conflicts, and mutual-exclusion groups. Selection remains local; it **never modifies signed manifest bytes**.

### Component schema

```json
{
  "schemaVersion": "3.0",
  "revision": 2,
  "digest": "<computed by publisher>",
  "components": [
    {
      "id": "core", "name": "Core", "files": ["mods/core.jar"],
      "version": "1.0.0", "required": true, "visible": false
    },
    {
      "id": "sodium", "name": "Sodium", "files": ["mods/sodium.jar"],
      "version": "0.5.2", "required": false, "visible": true,
      "dependencies": [{"id": "core", "versionRange": ">=1.0.0 <2.0.0"}],
      "conflicts": [{"id": "optifine", "versionRange": "*"}],
      "exclusiveGroup": "render-engine"
    }
  ],
  "presets": [{"id": "optimized", "name": "Optimized", "components": ["sodium"]}],
  "defaultPreset": "optimized"
}
```

All referenced component file paths must be included in the release `files` with ownership `optional`; they must not overlap and are SHA-256 verified by the native downloader. A signed catalog v1/v2 must not carry v3 rule fields. The backend recomputes the digest on draft edits; published manifests cannot be modified.

### Version and constraints

- Versions use strict `MAJOR.MINOR.PATCH`, with optional SemVer prerelease and build metadata. The constraints accept exact versions (`=1.2.3` or `1.2.3`), `>`, `>=`, `<`, `<=`, `^`, `~`, `*` and whitespace-separated AND clauses. `||` separates alternatives.
- Dependencies are transitive and always included. The actual resolved set is ordered by component position in the signed catalog; it is independent of map iteration order.
- A required or preset-selected component cannot silently be removed to resolve conflict. Unsatisfiable choices return an explanation before download and launch, identifying the incompatible components, version or group.
- A conflict can specify a target version range; a missing/empty range conflicts with every version.
- All named presets and the default selection are checked before a draft can be signed/published. Cycles anywhere in the declared dependency graph are rejected even if currently unselected.

### Failure codes (Go API error type)

`invalid_version`, `invalid_reference`, `invalid_range`, `invalid_group`, `cycle`, `version_mismatch`, `conflict`, `exclusive_group`, `unknown_preset`, `missing_dependency`, `limit`.

### Operational upgrade

1. Apply PostgreSQL migration `0063_dependency_conflict_resolver_0243` using the project migration runner. Existing migrations and schema versions remain valid.
2. Deploy Backend and Native Runtime together. Older native binaries do not accept schema 3.0 catalogs: **fail closed** rather than downgrade rules. Re-issue a new signed release with catalog schema 3.0; do not mutate published releases.
3. Update Desktop. Its topology preview is advisory, while the native Rust resolver and the signed-manifest verification authorize installation/launch.
4. CI: run `go test ./internal/model ./internal/dbmigrate` in `services/api` and `go test ./internal/dbmigrate` in `cli`. Build and test `runtime/neverruntime` with Rust installed, then run Desktop and Minecraft staging/rollback/security E2E before declaring GA.

### Deliberate scope boundaries

This version resolves **signed named presets** and their dependencies. Arbitrary per-player component toggles, OS/arch/Java/loader conditions, optional JVM actions, Admin graph editor and ServerBridge proofs belong to later roadmap milestones; do not treat the local UI preview or a component-ID list as server-verified proof of loaded JVM state.

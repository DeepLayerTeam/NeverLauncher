# NeverLauncher 0.24.2 — Component Topology & Presets

`Manifest.schemaVersion` remains **`3.0`**. `componentCatalog.schemaVersion` is **`2.0`**. Manifest v1/v2 and v3 with catalog v1 remain readable without rewriting signed bytes. The backend publisher and native client use an independently framed SHA-256 catalog digest (see `ComponentCatalogDigest0242` and Rust `digest_v2`) inside the signed Ed25519 release payload.

## Real installation behavior

1. Create an original v3 release draft and upload signed release files through existing admin package flow. Component files are marked `ownership=optional`, `required=false`, and their path, SHA-256 and size are signed as part of the release.
2. Update the draft using the authenticated version manifest update route with a `componentCatalog` object as shown below. `revision` and `digest` are **server generated**; client-provided values are not authoritative.
3. Sign/publish using the existing publish flow. Published manifests and their profileSnapshot remain immutable.
4. In Desktop > Profile, choose a signed preset and click Download/Update. The native installer resolves component IDs to file paths, stages **only selected components** plus all non-component files, verifies hashes, and atomically switches the managed release. A previous managed component that is no longer selected is removed transactionally; unknown/unmanaged user files are never removed as a side effect.
5. Resume/recover reads the signed manifest and the chosen preset from the durable local job journal; the active release journal stores the preset. Launch refuses to run when Desktop requests a different preset from the installed selection.

The `visible` field is **required** in schema v2. Hidden and `limited` components cannot be toggled directly in the 0.24.2 UI; they can only be activated by owner-signed presets or `required=true`. `default=true` is used when the catalog has no `defaultPreset`. A named preset is an explicit set of selected optional component IDs, always unioned with `required` components. `default` is not automatically unioned into named presets. Each component still owns at least one signed optional file; multiple components cannot own the same path.

### Example update payload

```json
{
  "componentCatalog": {
    "schemaVersion": "2.0",
    "components": [
      {"id":"core", "name":"Core", "description":"Required content", "files":["mods/core.jar"], "required":true, "visible":false},
      {"id":"sodium", "name":"Sodium", "description":"FPS improvements", "files":["mods/sodium.jar"], "categoryId":"performance", "groupId":"performance.optimization", "default":true, "visible":true, "metadata":{"author":"CaffeineMC"}},
      {"id":"shaders", "name":"Shaders", "files":["mods/shaders.jar"], "categoryId":"visual", "visible":true, "limited":true}
    ],
    "categories": [
      {"id":"visual", "name":"Visual"},
      {"id":"performance", "name":"Performance", "parentId":"visual"}
    ],
    "groups":[{"id":"performance.optimization", "name":"Optimization", "categoryId":"performance"}],
    "presets":[
      {"id":"light", "name":"Light", "components":["sodium"]},
      {"id":"quality", "name":"Quality", "components":["sodium","shaders"]}
    ],
    "defaultPreset":"light"
  }
}
```

`light` installs `core` + `sodium`, `quality` installs all three. Names, descriptions, category/group hierarchy, metadata, visibility and limited flags are included in the content hash and Ed25519 signature. Unknown IDs, duplicate IDs, reference cycles, excessive nesting and oversized metadata fail validation *before signing*.

## Safety and compatibility

- **No unsigned execution options.** v2 catalog contains no JVM args, classpath actions, URL overrides or local executable hooks. Preset input is only a signed preset ID.
- **Managed ownership.** All component paths are declared by the release; the transactional installer refuses to overwrite an unexpected user-owned file and backs up managed files for rollback.
- **Old releases.** Catalog v1 still installs every component. Existing Go catalog digests and Rust signed manifest JSON must remain byte compatible.
- **No implied O03/O04/O05 features.** Dependency/conflict/version solving, target conditions, and executable actions are deliberately not advertised.
- **Deployment requirement.** Run database migration 0062 before using schema v2. Old runtimes (0.24.1) reject schema v2 rather than silently skipping metadata.

## Validation

Run `cd services/api && go test ./internal/model`. Run native NeverRuntime tests (`cargo test -p neverruntime` from the Cargo workspace with Rust installed); test checksum and signing cross-language. Build Desktop (`npm ci && npm run build` in apps/desktop). Perform a real install of light, switch to quality, switch back to light and verify that only managed component paths change and a launch with a mismatched requested preset is rejected. Include abrupt termination during a preset switch and confirm release journal recovery.

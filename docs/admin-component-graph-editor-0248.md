# NeverLauncher 0.24.8 — Admin Component Graph Editor

This release adds a real Admin component editor for **unsigned Manifest v3 packages**. The Admin release wizard creates v3 packages; existing v2 releases and build-workspace-produced v2 packages are never silently upgraded. Do not edit signed, staged or published releases: create a new release version.

## Authoring and release flow

1. Create a new release package from **Release Workspace → Build**; the wizard requests `manifestSchemaVersion: "3.0"`.
2. Upload ordinary files as `required`/`managed`, and selectable component files as `optional`. Upload content is hashed by Backend, not by Admin JS.
3. Open **Component Graph Editor**. Add stable component IDs, names, descriptions, categories, nested categories/groups, presets, a default preset and metadata. Assign **each optional file to exactly one component**.
4. Edit `required/default/visible/limited`, component SemVer, dependency ranges, conflicts, exclusive groups, OS/arch/Java/Minecraft/loader/permission conditions (`schemaVersion: "1.0"`), and owner-signed actions `File`, `ClassPath`, `JvmArgs`, `ClientArgs`. `File`/`ClassPath` reference files owned by that same component. Safe argument allowlists still apply.
5. **Check on Backend** before saving. The response reports SHA-256 digest, new revision, validation errors, default and every explicit preset with its deterministic dependency graph. Local lint is only a convenience; Backend enforces limits, ownership, constraints and signature-integrity rules.
6. **Save validated catalog** with optimistic concurrency (`expectedRevision`). The repository locks the row and rejects changed revision. After successful save, proceed to package Validate → Sign → Stage → Integrity → Publish. Signing independently rechecks the graph, so a legacy API call cannot skip it.

### Graph validation vs environment

The graph preview validates **static combinations** (dependency closure, SemVer, cycles, conflicts, exclusive groups) and the complete declaration schema. It does not forge runtime context or permissions. OS/arch/Java/Minecraft/loader and user entitlement constraints are checked again by native runtime with trusted context. As of 0.24.4, permission-only components remain unavailable until server-verified entitlement evidence is implemented.

### Integrity and updates

`GET /api/v1/packages/{packageId}/component-catalog` returns current catalog, state and manifest files. `POST /.../component-catalog/preview` is side-effect free. `PUT /.../component-catalog` accepts `{expectedRevision, catalog}` and atomically persists the recomputed v5 catalog **only while status is `draft`**. Neither endpoint accepts attacker-supplied digest as authority. API authorization is scoped to `project:read` and `release:prepare` on the package project, respectively.

Uploaded optional files may temporarily be unowned while the draft is being edited. The catalog save path validates the **complete candidate manifest** and can repair that intermediate state without allowing a modified profile snapshot, another project, or a change to a signed/published release. `PUT` returns 409 if another administrator updated the draft.

### Test matrix

- Go component resolver and structural-digest regression tests (`go test ./internal/model`).
- HTTP lifecycle regression: create v3 → upload optional → preview → save → reject stale revision → refuse injected `-javaagent` action (`go test ./internal/httpapi -run TestComponentCatalogEditorLifecycle0248`).
- Node Admin editor tests for reference renames, removed items, ownership and version constraint parsing (`npm test`).
- Full Admin build (`npm ci && npm run build`) and full API test suite, PostgreSQL integration and real Minecraft launch require external toolchains/dependencies and were **not run** in the restricted editing environment.

The general Build Workspace introduced in 0.22.6 continues to create traditional v2 builds. To author optional components in 0.24.8 use the v3 package route in the Release Workspace.

# 0.24.1 — Signed component catalog (Manifest v3)

Production contract added in 0.24.1. Old v1/v2 releases remain readable and their signed JSON is **not** rewritten.

## Publishing an actual catalog

1. Apply database migration `0061_signed_component_catalog_0241.sql` before enabling the new backend.
2. Use authenticated `POST /api/v1/admin/projects/{projectId}/versions` with `{"profileId":"vanilla","channel":"stable","version":"0.24.1-demo","manifestSchemaVersion":"3.0"}`. This writes a *new* v3 draft and pins its existing immutable profile snapshot. Existing v2 drafts cannot be upgraded.
3. Upload release files using the same secured package file pipeline as v2. Files belonging to a component use `ownership="optional"` and `required=false` (this describes ownership, **not** whether they are installed in 0.24.1); do not use paths outside managed ownership. The file URL, SHA-256 and size must pass normal release publication checks.
4. Send `PUT /api/v1/admin/projects/{projectId}/versions/{versionId}/manifest` with the normal runtime/minecraft properties if needed, plus `{"componentCatalog":{"components":[{"id":"performance.sodium","name":"Sodium & friends","files":["mods/sodium.jar"]}]}}`. The backend **computes** the digest and increments the catalog revision, then clears any old signature. The caller cannot provide an independent digest or arbitrary JVM actions. Every v3 optional file must have exactly one component owner.
5. Run the existing package `sign`, `stage`, integrity-check and `publish` sequence. The signer covers the **entire** Manifest v3, including component catalog, profile snapshot and file hashes. Published snapshots are immutable in the API and the database.
6. NeverRuntime 0.24.1 verifies pinned Ed25519 signatures and the catalog digest, stable IDs and file membership **before** downloading/repairing/launching. Its transactional installer treats all v3 catalog members as installed payloads, SHA-256 verifies them, and refuses incomplete staging. Desktop displays the released manifest and uses the native validated installer.

## Signed format

`componentCatalog` has `schemaVersion="1.0"`, `revision >= 1`, lowercase stable `id`, `name`, `files` with relative signed manifest paths, and SHA-256 `digest`. Digest is computed over the component array in order with domain prefix `neverlauncher.component-catalog.v1\0`, four-byte unsigned big-endian array counts, and four-byte unsigned big-endian length-prefixed UTF-8 strings (`id`, `name`, then each file path). IDs and paths are unique; paths may only refer to signed optional-owned files, not generated/user-owned or required files. The signed manifest itself is the trust boundary: a digest alone is not an authentication mechanism.

**0.24.1 behavior:** every catalog component is deployed (no end-user enable/disable yet). `required/default`, groups, presets, conflict/dependency resolver, conditions, typed JVM actions and player selection remain work for 0.24.2+. An old CLI updater rejects Manifest v3 rather than dropping component metadata. Use native NeverRuntime 0.24.1 for v3 clients.

**Verification:** `GOPROXY=off go test ./internal/model ./internal/dbmigrate` under `services/api`, `GOPROXY=off go test ./cmd/neverlauncher` under `cli`, and `cargo test --manifest-path runtime/neverruntime/Cargo.toml v3_catalog_ed25519_sign_verify_and_tamper_0241` when Rust tooling and dependencies are available. Integration testing on a running backend/real PostgreSQL/Minecraft is additionally required before declaring a production deployment certified.

# Component conditions in signed catalog 4.0 (Launcher 0.24.4)

Catalog `schemaVersion=4.0` is embedded in signed Manifest v3. Per-component optional `conditions` has **mandatory** `schemaVersion=1.0`. The component's conditions are framed into the catalog's v4 SHA-256 digest, covered again by the release Ed25519 signature. The old v1/v2/v3 digest algorithms remain byte-for-byte unchanged. Unknown condition keys are rejected by Runtime; invalid or v4-only conditions in older schemas are rejected.

Supported AND predicates: `os` (`windows`, `linux`, `macos`), `arch` (`x86_64`, `aarch64`), `javaMajorMin`/`javaMajorMax`, `minecraftVersions` (exact values, including snapshots), `minecraftVersionRange` (MAJOR.MINOR.PATCH SemVer), `loaders` (`vanilla`, `fabric`, `quilt`, `forge`, `neoforge`), `loaderVersionRange` (SemVer) and `permissions` (all granted). Arrays in each predicate are OR. Empty fields are unrestricted. The native resolver derives OS and architecture from the executable and game/loader/Java target from the verified manifest. **A user-supplied permissions array is never accepted by the native resolver.** Until the server issues a separately verified, session-bound entitlement attestation, any catalog component with nonempty `permissions` is fail-closed on the client, including required components. Authorization must be based on verified server grants, not desktop JSON.

Automatic defaults whose conditions fail are skipped, while an explicitly selected preset, required component or transitive dependency with unsatisfied conditions fails before staging/download. For example:

```json
{ "id":"perf-fabric", "name":"Performance", "version":"1.0.0", "files":["mods/perf.jar"], "default":true, "visible":true,
  "conditions":{"schemaVersion":"1.0", "os":["linux","windows"], "arch":["x86_64"], "javaMajorMin":17, "minecraftVersions":["1.21.1"], "loaders":["fabric"]}}
```

The Go code supports caller-provided `ComponentEnvironment0244.VerifiedPermissions` **only when populated by trusted server authorization**, never raw JSON from the client. Native execution currently rejects permissions-gated components without attested proof. JVM version is resolved from the release's signed target and the Java launcher enforces version consistency at launch; an upgrade is required if the actual Java executable changes independently. Loader/Minecraft version ranges accept SemVer only; use exact version arrays for snapshot and non-SemVer identifiers.

## Build checks

- `cd services/api && go test ./internal/model ./internal/dbmigrate`
- `cd cli && go test ./internal/dbmigrate`
- `cd runtime/runtime && cargo test` (requires Rust toolchain)
- `cd apps/desktop && npm ci && npm run build`

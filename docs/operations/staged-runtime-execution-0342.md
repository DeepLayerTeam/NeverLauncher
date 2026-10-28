# 0.34.2 — Real staged package execution (V01 / V02)

This is executable staging validation, **not stable release certification**.
The 0.34.1 database and application stable gate remain in force even if every
staged execution report says `passed`.

## Packaging the actual client

1. Build the Minecraft client with the existing Client Factory **before** signing
   the Backend release, or deliver another complete executable Minecraft client
   with pinned Minecraft/loader dependencies. Include ALL real runtime files
   (`versions/`, `libraries/`, `assets/`, `natives/`, mods, runtime metadata)
   as signed package files. No runner stage may build a substitute Minecraft client.
2. Sign the release, stage it, and run its real package integrity-check. The Backend
   `POST /api/v1/packages/{packageId}/staged-runs` returns an expiration-bound
   read/report grant for that precise integrity-passed package digest.
3. Dispatch `.github/workflows/staged-package-runtime-0342.yml` with the exact
   `package_id` or use the production release candidate workflow. Configure
   protected GitHub Environment `runtime-validation-staging` and:
   - Variable `NL_STAGED_BACKEND_URL` (TLS URL to Backend).
   - Variable `NL_STAGED_MANIFEST_PUBLIC_KEY`: project **pinned** 64-character
     Ed25519 public key hex, independently provisioned (not read from received manifest).
   - Environment secret `NL_STAGED_RUNNER_OPERATOR_TOKEN` with project-scoped
     `release:prepare` only. Never expose release signing keys or production data.
4. The isolated runner gets an HMAC-bound grant (90 minutes), retrieves the
   backend-verified signed manifest and exact staged files, checks every SHA-256
   and size, then invokes normal `nl client install` and `nl client verify`.
   Finally it uses **NeverRuntime `launch`**, the installed client root, the
   same signed manifest and operator-pinned key, and selects the signed Java
   major on the GUI-capable worker. No Client Factory lock or rebuild is required.

## Evidence

`GET /api/v1/packages/{packageId}/staged-runs` returns PostgreSQL-backed
observational reports with separate `manifest-files`, `materialization`, and
`startup` stages. Hash and size mismatches fail `manifest-files` and prevent
installation. Missing or invalid pinned signing key, Java, native runtime plan, or game files fails the runtime stage.
Startup is **inconclusive** even after the legacy runtime probe succeeds: positive
menu readiness, cross-loader readiness and matching-server join become
mandatory only in later V03/V04/V07 stages. Reports from a runner are **not**
trusted certification and do not enable stable publication. The Backend also
rejects stale grants, cross-package grants, replays of report run IDs, modified
storage bytes and any post-grant manifest/file metadata drift.

The public `/api/v1/files/...` route now serves only published releases. Staged
bytes are readable only through the short-lived grant-specific delivery route.
Never publish a staging grant in Actions logs, artifact uploads, issue trackers
or diagnostics. The result report never includes the grant or login token.

## Local validation

```
python3 -m unittest e2e/scripts/test_run_staged_package_0342.py -v
cd cli && go test ./cmd/neverlauncher -run 'TestRuntimeCertification02712|TestClientPackage|TestClientFactory0271' -count=1
cd ../services/api && go test ./internal/httpapi ./internal/repository ./internal/dbmigrate -run 'TestStaged.*0342|TestStable.*0341|TestEvaluateAppliedSealedCatalog' -count=1
```

Run the actual GitHub job on a GUI-capable worker with Minecraft installed
as a **staged signed artifact**. Unit tests with fake HTTP servers do not prove
that a real Minecraft window reached a specific readiness state.

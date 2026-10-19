# NeverLauncher 0.23.0 — Profile & Build Workspace GA qualification

## Scope

0.23.0 integrates Profile/Manifest v2, pinned profile revisions, deterministic
launch inputs, file ownership, Gravit conversion and Build Workspace through
stage/build into the existing signed/durable publication pipeline. It does **not**
re-sign older public Manifest v1 releases or authorize unsupported Gravit
classloaders/actions. A Git checkout or a patched-source ZIP is **not** itself a
production certification or a signed distributable.

## Blocking corrections in this release

- `SQLRepository.CreateBuildWorkspace` verifies `RowsAffected()` on
  `INSERT ... ON CONFLICT DO NOTHING`. A duplicate workspace ID always returns
  `ErrConflict`; comparing timestamps after the insert is not sufficient.
- Both repository implementations enforce pinned `BuildSettings` (Java,
  Minecraft/loader, memory, classpath, environment, file rules, tool versions)
  and reject invalid state transitions. The package reservation cannot be
  redirected to another release. Built workspace records are immutable.
- Upload/stage refuse writes after a workspace is reserved for a release
  package, so resumed build operations cannot silently change the inputs.
- New release tests cover actual API preview/commit of Gravit profiles, the
  existing HTTP import/scan/diff/stage/validate/build pipeline, real PostgreSQL
  atomic profile + workspace creation and concurrent CAS, protected client
  data on repair, rollback and stale update rejection.

## Upgrade and rollback

1. Back up PostgreSQL and object storage. Do not overwrite or regenerate
   existing `ProfileSnapshot` revisions or signed Manifest v1/v2 bytes.
2. Run the migration tooling built into the matching API/CLI release.
   Migrations `0056` through `0060` implement Profile v2, immutable revision
   history, signed file rules, workspace persistence and revisioned channel
   heads. No destructive rewrite of these migrations is included in 0.23.0.
3. Deploy matched API, CLI, NeverRuntime and Desktop artifacts from the **same
   certified source commit**, then check health and rollout on an isolated
   staging project before advancing stable.
4. A database rollback across the 0.22.x schema boundary is not automatic.
   Restore from a verified backup instead of applying a destructive down SQL
   migration. Do not expose stale/unsigned profile manifests as a fallback.

## Required automated certification

Run from a clean checkout at the exact release commit:

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
python3 scripts/release/test_certify_profiles_ga_0230.py
# Point to a *dedicated*, disposable real PostgreSQL database:
export NEVERLAUNCHER_TEST_POSTGRES_DSN='postgres://USER:PASSWORD@HOST:5432/DB?sslmode=require'
export NEVERLAUNCHER_SOURCE_COMMIT="$(git rev-parse HEAD)"
python3 scripts/release/certify-profiles-ga-0230.py
NEVERLAUNCHER_PREFLIGHT_STRICT=1 bash scripts/release/preflight.sh
```

The GitHub `production-release-candidate` workflow provisions PostgreSQL 17
and executes the dedicated Profile GA test matrix under Go's race detector.
A JSON report is emitted at `dist/ga-certification/profiles-0230.json`.
Any missing, skipped, failed or timed-out mandatory test fails the job.
Release bundle generation requires the **passed** artifact from the **same**
commit SHA and version, in addition to the original Admin, Guard, Java,
compatibility, device-trust, Windows Authenticode and macOS notarization gates.
The runtime CI job also requires Rust tests/clippy and a real Linux build;
Windows/macOS deliverables are independent platform gates.

Release still requires full client/loader launch E2E, server bridge attestation,
production-build smoke tests, signing and notarization. Absence of these
external proofs blocks GA promotion. A local passing subset cannot certify
0.23.0 for public distribution.

## Manual end-to-end acceptance

- Import a real Gravit profile, review mapped/transformed/manual/blocked fields.
  Reject unknown actions, flags and legacy classloaders; resolve manual issues.
- Stage and build with pinned ProfileSnapshot and immutable content digests.
  Confirm signed release publication rejects an obsolete channel revision.
- Interrupt a staged client update and verify recovery to a consistent version.
  Ensure `saves`, `screenshots`, user resource packs/mods and allowed settings
  remain unchanged by install, repair, cleanup and rollback.
- Verify identical signed inputs resolve to the same static LaunchPlan digest,
  independent of ephemeral local paths and session tokens. Confirm launch of
  Vanilla and supported loaders on the target Java versions and platforms.

## Local validation limitations

A source-only environment without a Rust toolchain, PostgreSQL, npm dependency
cache, release signing identities or real Minecraft installation must report
those tests as *not run*. Do not fabricate successful results or certification
artifacts. The exact-commit workflow must pass before declaring a GA release.

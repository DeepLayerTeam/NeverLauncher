# NeverLauncher 0.34.0 — Migration Center GA acceptance

## Production release policy

`0.34.0` ships the MIG01–MIG13 implementation together with the **executable** `tools/migration-ga` acceptance runner. The version number by itself is not evidence that a Gravit project can safely switch production traffic. An operator must validate an exact Gravit 5.7.x patch version/build, a signed Never release and the actual player/server data on an isolated test deployment. The runner exits nonzero and issues no success certificate if any required check is absent or fails.

The runner is not a substitute for independently stopping Gravit database/world writers. Never can lock its own delivery channel, not third-party Gravit processes. Nor does the runner create VMs: launch it on an isolated CI runner with separated databases, worlds, identities and trust stores. **Do not point the E2E runner at production Minecraft worlds**. Do not use synthetic pass/fail scripts or unchecked mocks as release evidence.

## Execution

1. Prepare a real Gravit 5.7.x project ZIP, an imported Never migration run with an immutable reviewed MIG13 report, an active tested cutover channel and a separate disposable Minecraft E2E environment. Record the exact signed target release's SHA-256 from the `cutover_scope:` evidence of the MIG13 report.
2. Provide an independent Ed25519 PKCS#8 `PRIVATE KEY` for the GA auditor and publish its corresponding Ed25519 `PUBLIC KEY` out-of-band. This is **not** a Gravit or Never launch-signing key. Keep the private key on the isolated runner, mode `0600` or equivalent.
3. Configure the 13 required probe executables (see below) in a private JSON plan. Each program actually performs the test and prints one JSON receipt to stdout; its full raw logs are written to a *fresh*, nonempty, bounded evidence file with an absolute path and returned SHA-256. **All probes must run**—there are no warning-only cases or accepted skips.
4. From the repo root execute:

```bash
export NEVERLAUNCHER_MIGRATION_GA_TOKEN='...'
go -C tools/migration-ga run . certify --plan /secure/ga-plan.json --output /secure/ga-result.json
go -C tools/migration-ga run . verify --certificate /secure/ga-result.json --public-key /secure/ga-auditor.pub.pem
```

The tool has its own `go.mod` in `tools/migration-ga/` and builds independently of the Backend. Run tests with `cd tools/migration-ga && go test -race ./...`.

The JSON plan fields are `backend` (HTTPS origin, or numeric localhost), `runId`, `projectId`, `sourceArchive` (absolute path), `sourceVersion` (verified `5.7.0`–`5.7.12` patch, matched to `LaunchServer.jar`), `trustedGravitJarSha256` (SHA-256 from a separately authenticated official Gravit distribution fixture), `targetReleaseSha256` (the active release digest), `commitSha` (exact 40- or 64-character Git commit ID), `signingKey` (Ed25519 private key PEM path), and `checks` (array). Each check has `name`, `command` (argv array, **not a shell command string**) and `timeoutSeconds` (1–900). Credential `NEVERLAUNCHER_MIGRATION_GA_TOKEN` is removed from child environments.

Required independent cases, matched by name exactly:

- `fileauth-login`, `sql-login`, `official-login` — unchanged player credentials/provider continuity and new login where required
- `forge-launch-join`, `neoforge-launch-join` — real client launch and server join
- `optional-presets`, `skins` — mods, skin and texture continuity
- `uuid-world-plugin-data`, `admin-permissions` — UUID and world/plugin inventory, rights, economy and admin checks
- `serverwrapper` — working replacement ServerBridge node and authenticated join
- `desktop-cache-install` — official signed installer plus verified cache adoption
- `staged-cutover-canary`, `operational-rollback-drill` — externally fenced writer routing and reconciliation drill

Each executable writes a JSON receipt with `runId`, `name`, `reportSha256`, `sourceSha256`, `sourceVersion`, `targetReleaseSha256`, `passed`, `evidenceFile` and `evidenceSha256` corresponding to actual execution. For `uuid-world-plugin-data`, it also supplies the *full* `sourceUuids`/`targetUuids` lists and `sourceWorldSha256`/`targetWorldSha256` plus `sourcePluginSha256`/`targetPluginSha256`. The runner compares UUID sets to the MIG13 identity map and requires all digests to match.

A success bundle is signed with the auditor key and contains every check result digest and evidence checksum. Run `verify` with the independently trusted public key; it verifies the signature, full required-case matrix and freshness (72 h). The underlying evidence files and live environment still need operator review. A signed bundle is evidence of the executed checks, **not proof that the external check programs were truthful**. The full system's release approval must also verify the actual release signatures and external infrastructure fencing.

## Security controls and fail-closed behavior

- The source ZIP must be byte-for-byte identical to the MIG03 source SHA-256 recorded by Backend. The runner additionally opens `LaunchServer.jar`, compares its actual bytes to a separately pinned official Gravit binary SHA-256 and matches the product/version from the JAR manifest to the configured 5.7.0–5.7.12 patch. A JAR manifest alone is not proof of upstream provenance; report SHA-256 is recomputed locally and the report must match the immutable MIG13 review.
- Only a route with active verified cutover and the exact signed target digest may be certified; cancelled, staged-only and blocked projects are rejected.
- All required MIG02–MIG12 reports must be `verified`; unknown auth/launch modules, ambiguous UUIDs, missing authentication or failed rehearsal block certification.
- Every child process must exit successfully and return real fresh evidence bound to the current run, report, source and target. Timeout, missing evidence, invalid checksum or changed player UUID/world/plugin data fails the job.
- The backend report is fetched again after running the checks. If it changed, no signature is written.
- The private result is fsynced into a temporary owner-only file and atomically published without replacing an existing certificate.
- An independent, separately protected audit key prevents a modified result from being accepted by `verify` without a valid Ed25519 signature. The signed result must be distributed alongside archived raw E2E receipts.

## Release exit checklist

The `.github/workflows/gravit-migration-ga-0340.yml` workflow checks full Go Backend, PostgreSQL integration, CLI, Admin, Linux/Windows/macOS Desktop compile/test and the standalone runner. **Tag/dispatch GA certification requires** a separately isolated, independently provisioned runner (`migration-ga-isolated`) with real Gravit/Minecraft fixtures and securely configured signing material. Missing infrastructure or E2E results fails the release gate; there is no automatic success fallback. The workflow cannot be represented as passed until GitHub actually executes it successfully.

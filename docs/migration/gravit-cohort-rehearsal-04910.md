# NeverLauncher 0.49.10 — three-project live Gravit migration and client update rehearsal

This is an **operator-run executable** for three **independently sourced real**
Gravit projects. It does not generate project fixtures, invent Minecraft observations,
run a mock server, forge Backend migration reports, change production traffic or
approve 0.50.0 GA. The downloaded game client, licensed account, server and RCON
connection must already be working in three isolated staging environments.

## What is actually executed

For **each** of exactly `fileauth-single`, `sql-modded`, and `proxy-network`:

1. Pin the bytes of the CLI executable, actual Gravit source ZIP, profile mapping,
   previously obtained multi-profile dry-run, signed update package and delivery
   manifest to operator-reviewed SHA-256 hashes. Reject reused project/run/source,
   symlinked test probes, an unprotected output directory, or a missing stage.
2. Replay `launcher migrate gravit verify-dry-run-all` against the live Backend,
   proving the same source, mapping and unmodified target are still present.
3. Execute `launcher migrate gravit import-content-all` against the production
   implementation of staged encrypted workspaces (no fake import receipt).
4. Execute `launcher migrate gravit rehearse`: actual foreground client launch,
   RCON-confirmed UUID join, seven independent checks and Backend's PostgreSQL
   verification of migrated UUIDs, modules, auth, trust and content. **Require
   `ready=true`, no blockers and `cutoverAllowed=false` from the Backend.**
5. Execute the real signed `launcher update components` on the isolated installed
   Desktop/Guard/Runtime files with `--package`, SHA-256 pin and verified delivery
   manifest. Never enable the development/unpinned bypass. Confirm `committed`,
   the expected target version and the changed installed executable bytes.
6. Execute `launcher migrate gravit rehearse-local` on the now-updated executable,
   using the SAME real process + loopback RCON + seven-probe mechanism. Require
   the new client executable SHA-256, the same player UUID and the same source
   and target world/inventory/permission snapshots. This second report is
   **local-only** and cannot overwrite the original immutable PostgreSQL
   rehearsal receipt or claim cutover authorization.
7. Write owner-only, non-overwriting per-project receipts. Only if **all three**
   finish, write `cohort-04910.json` with the explicit status
   `isolated-stage-pass-not-production-GA` and `productionGA: false`.

After a failed or interrupted import/update, stop and inspect the Backend
workspace, package updater journal and persisted reports. An interrupted run
is **not** automatically resumed or silently retried; it may require a new
reviewed migration run and isolated stage. This tool never switches production.

## Setup

Build `launcher-cli` from the pinned project sources and verify the published
signed package bytes using the release process. For each project, prepare
`migration-runs` in the PostgreSQL Backend, complete compatibility/Gravit
source assessment, the MIG03–MIG08 identity/auth/security/module prerequisites,
prepare and obtain a **real** `dry-run-all` report, prepare a genuine Minecraft
server in a disposable environment, and install an old client package to update.

Each stage must contain the existing `.migration-stage.json`,
`source-snapshot.json`, `target-snapshot.json`, `live-session.json`, the protected
`rcon-password`, and the seven **executable** `probes/{launch,login,join,skins,loader,optional,admin}`.
Consult `docs/migration/gravit-live-rehearsal-0447.md` for the exact format,
RCON and test-account requirements. Each probe must actually exercise its named
behaviour; returning a constant success is not acceptable evidence.

**0.49.10 additional requirement:** the executable in `live-session.json`'s `clientPath` must be the real installed client binary, not a stable wrapper.
Place `installRoot` **inside** the isolated `stage`, and set `installedComponent`
to the relative path from `installRoot` to that executable. The stage-relative
`clientPath` must resolve to the **same file**. This binds the pre/post Minecraft
join observations to the executable that was updated and prevents unrelated
binary updates from being counted as a successful client upgrade.

Create a private config, for example `/srv/secure/cohort.json` with mode 0600:

```json
{
  "format": "never/gravit-three-project-rehearsal/v1",
  "launcher": "/opt/never/launcher-cli",
  "launcherSha256": "<sha256>",
  "backend": "https://staging-backend.example.org",
  "projects": [
    {
      "referenceClass": "fileauth-single",
      "runId": "<existing-run-id>",
      "projectId": "<existing-project-id>",
      "sourceZip": "/srv/secure/fileauth/source.zip",
      "sourceSha256": "<sha256>",
      "mapping": "/srv/secure/fileauth/mapping.json",
      "mappingSha256": "<sha256>",
      "dryRunReport": "/srv/secure/fileauth/dry-run.json",
      "dryRunReportSha256": "<sha256>",
      "inventorySha256": "<sha256>",
      "stage": "/srv/isolated/fileauth",
      "installRoot": "/srv/isolated/fileauth/client",
      "installedComponent": "launcher",
      "updatePackage": "/srv/secure/fileauth/updated-client.tar.gz",
      "updateSha256": "<sha256>",
      "deliveryManifest": "/srv/secure/fileauth/DELIVERY_MANIFEST.json",
      "deliverySha256": "<sha256>",
      "expectedUpdatedVersion": "0.49.10"
    }
  ]
}
```

The example shows **one** entry for readability; supply **three**, each with a
separate run ID, source archive/digest, project ID, stage and install root, using
`fileauth-single`, `sql-modded`, `proxy-network`. `client/launcher` is illustrative:
use the real installed component path from the validated signed package and set
`live-session.json`'s `clientPath` accordingly. Keep update package bytes and
manifest outside the install roots being upgraded.

```bash
chmod 0600 /srv/secure/cohort.json
install -d -m 0700 /srv/private/cohort-04910
read -rs LAUNCHER_TOKEN && export LAUNCHER_TOKEN
python3 tools/gravit-port/rehearse_cohort_04910.py \
    --config /srv/secure/cohort.json \
    --output-dir /srv/private/cohort-04910 --preflight-only
python3 tools/gravit-port/rehearse_cohort_04910.py \
    --config /srv/secure/cohort.json \
    --output-dir /srv/private/cohort-04910
unset LAUNCHER_TOKEN
```

Secrets are passed only through the environment. The Go rehearsal probe
strips the token and production credentials from the seven subprocesses. No
shell command from the uploaded ZIP is executed. All report paths are
non-overwriting and private; do not publish them with bearer tokens or RCON
passwords. Prefer short-lived MFA-elevated operator sessions and a dedicated
isolated runner.

## Acceptance boundary

- An offline run of `--preflight-only` is **not** a migration, a signed update,
  a Minecraft join or a GA approval.
- Python regression tests exercise fail-closed validation and orchestrator
  control flow with synthetic test inputs; Go tests exercise the **real CLI**
  Minecraft/RCON protocol against a controlled local test listener. Neither
  substitutes for three externally provisioned Gravit projects or a live
  official Minecraft session.
- The initial `rehearse` is Backend-authoritative. The post-update
  `rehearse-local` is supplementary. It **never** sets `ready=true` or
  `cutoverAllowed=true`, posts to the Backend or certifies a production release.
- For independent **GA** certification, independently run all 36 project
  checks with `tools/migration-ga verify-cohort-live` on exact uploaded evidence
  and obtain an independent operator sign-off. See
  `docs/migration/gravit-integration-acceptance-0449.md`. Update/rollback of
  worlds or network cutover require the separately fenced MIG11/MIG12 steps.

The provided repository archive contains **no** three live Gravit installations,
real Minecraft accounts, running servers or signed update package installations.
Their acceptance remains BLOCKED until independently executed.

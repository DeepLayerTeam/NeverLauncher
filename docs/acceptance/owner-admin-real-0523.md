# NeverLauncher 0.52.3 — Real Owner & Admin E2E

This is a **destructive** acceptance of a brand-new, isolated Standard installation,
**not** an API simulator, release attestation, certificate authority, or GA override.
The existing `scripts/acceptance/minimal_live_e2e_0378.py` is extended in 0.52.3
to actually create/update an admin project and profile/channel, check access,
audit, sessions, SIGTERM/SIGKILL persistence and backup/restore on real SQLite.
The production release-bundle acceptance invokes this same Minimal runner on
the final Linux API binary, with release/checksum validation as before.

## Standard physical prerequisites

1. Dedicated self-hosted Linux Docker machine, with no pre-existing Compose
   containers, volumes or networks for a *unique* project `nl0523` followed by
   8–20 lowercase alphanumeric characters. No general production credentials.
2. Private Standard `.env` (0600), valid root-owned TLS key, publicly trusted
   certificate for `LAUNCHER_PUBLIC_URL`, real accessible public HTTPS :443,
   PostgreSQL, and `LAUNCHER_IMAGE_TAG=0.52.3`, `LAUNCHER_REPOSITORY_DRIVER=postgres`,
   `LAUNCHER_DEPLOYMENT_MODE=standard`. Set `LAUNCHER_SOURCE_COMMIT` to the exact
   tested SHA (`GITHUB_SHA` in CI). Set `LAUNCHER_COMPOSE_PROJECT` to that unique name.
3. A *real* dedicated Minecraft JVM with running Launcher Host Supervisor,
   ServerBridge plugin that can post signed v3 heartbeats to this new Backend,
   and an externally installed RemoteControl endpoint with a correctly pinned
   TLS certificate and token. DO NOT use a fake Java executable or offline mock.
4. Three private host files, owned/readable as uid 10001 inside the API
   container, each mode 0600 (no symlinks), referenced by absolute host paths
   in `.env`:

   ```env
   LAUNCHER_0523_HOST_TARGETS_FILE=/private/nl0523/targets.json
   LAUNCHER_0523_HOST_CA_FILE=/private/nl0523/ca.pem
   LAUNCHER_0523_HOST_TOKEN_FILE=/private/nl0523/token
   ```

   The targets JSON maps the dedicated server ID to
   `{ "url": "https://real-remote-host", "nodeId": "real-host-node-id", "caFile": "/run/owner0523/ca.pem", "tokenFile": "/run/owner0523/token" }`.
   The extra Compose file is activated only by these three variables and a
   strictly isolated project name. An ordinary production installation is
   unaffected.
5. Private registration JSON (0600) for the already-running Java node with
   its genuine public Ed25519 key, for example
   `{ "id": "dedicated-paper", "name": "Dedicated Paper", "kind": "paper", "keyAlgorithm": "ed25519", "publicKey": "<real base64 public key>" }`.
   The runner attaches it to the newly created test project/profile. The node
   must actually reconnect and produce a fresh signed heartbeat; registration
   alone does not count as a live server. Do not put a private key in this JSON.
6. A pre-existing data file belonging to the dedicated Minecraft project or
   player, accessible in the runner's filesystem. For unchanged data, prefer a
   stable player/plugin state marker outside mutable game metadata. It is read
   (never modified) and SHA-256 compared across start/stop/restart and API
   service restarts. This marker alone does **not** prove the whole world is
   crash-consistent; extended world DR is covered in OPS acceptance.
7. Strong one-time bootstrap token and owner password (0600 file). The runner
   enrolls real TOTP and obtains a fresh MFA token; never supply a pre-forged
   `mfa=true` session. The disposable owner can be deleted with the test volume
   only after acceptance data has been collected.

The real runner executes production `compose check/up`, verifies HTTPS and
PostgreSQL readiness, invokes production `first-admin`, rejects unauthenticated
and repeated bootstrap, creates first project and performs authenticated Admin
CRUD. It registers the real node, waits for fresh signed JVM heartbeat,
performs a real console command with game-agent acknowledgement, performs
stop/start/restart with pinned RemoteControl and receipt reconciliation,
checks persistent data and idempotency, restarts the entire Compose stack,
then re-authenticates and reads all project/profile/channel/installer data.
The runner stops containers but **never purges volumes**. A failure retains
project data for forensic review; do not point it at a production project.

Example command (use ONLY on the dedicated, prepared host):

```bash
python3 scripts/acceptance/owner_admin_real_0523.py \
  --env /private/nl0523/.env \
  --email owner-0523@example.net --password-file /private/nl0523/owner.password \
  --server-id dedicated-paper --bridge-registration-file /private/nl0523/node-public.json \
  --world-marker /mnt/dedicated-minecraft/plugins/Example/player-state.dat \
  --report /private/nl0523/owner-report.json \
  --isolated-destructive-acceptance
```

**Fail-closed acceptance:** missing Docker/HTTPS/trust files, pre-existing
namespace, failed owner creation, a wrong backend/version/commit, missing or
stale signed heartbeat, rejected/unacknowledged console command, host result
remaining `accepted`/`indeterminate`, missing user file, or any persistence
mismatch yields BLOCKED with a nonzero exit code. Reports are atomic mode
0600 and do not contain tokens, recovery codes, passwords or raw responses.

Manual CI dispatch uses a protected environment and a dedicated self-hosted
runner with label `neverlauncher-0523-dedicated`; supply the six `NL_0523_*`
GitHub environment variables as *paths/identifiers*, not credentials. Without
this physical runner the Standard result is **BLOCKED**, regardless of local
Python tests. This stage does **not** establish six-platform client/Minecraft
compatibility, independent GA, full world RPO or final package signatures.

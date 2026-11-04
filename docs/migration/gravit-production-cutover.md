# NeverLauncher 0.49.11 — промышленное переключение входящего трафика Gravit

**Production source implementation, not independent GA certification.** This is a **real two-phase operator tool** for one already-staged Gravit migration `runId/profileId/channel`, operating a **dedicated HAProxy v2/v3 runtime Unix socket** for *both* the public login and game TCP backends. It calls the existing PostgreSQL-backed NeverLauncher route activation, verifies the actual target login on HTTPS, opens the new HAProxy servers, and requires a real local Minecraft launch/RCON join through the configured public game endpoint. It cannot create a Minecraft account, a signed release, a certified MIG10 stage, a source backup or a Linux host.

No distributed transaction can atomically change PostgreSQL, two independent HAProxy backends, external Gravit auth state, DNS and Minecraft world storage. Consequently, failures are **fail-closed**: servers remain in `MAINT` and operator reconciliation is required; the tool never silently reopens the old source or discards new world writes.

## Необходимые условия (реальные, а не созданные тестовыми фикстурами)

- Already completed 0.49.10 real independent source/rehearsal, staged Never release and verified signed target, target running on PostgreSQL, with stable runtime permit when required. Backend must expose `/api/v1/admin/migration-runs/RUN/cutovers`; CLI must actually work on the operator machine.
- A dedicated **single HAProxy process** with separate `auth` and `game` backends. Each backend contains exactly the old and new server, or all other servers are already `MAINT`. HAProxy has functioning health checks: `UP` means healthy. The admin socket must be a real local Unix socket owned by root or the operator executing this tool. Keep the HAProxy configuration and runtime state controlled by the same trusted operator.
- Before prepare, the old auth/game servers are `UP`, new servers are `MAINT`, and clients are informed of a maintenance window. The source Gravit account authority, all relevant world writers, proxy/ingress alternatives, caches, queues and scheduler workers must be inventoried and quiesced. A **single** `systemd` unit receipt cannot prove that every writer has stopped.
- Independent, verified backups of Gravit + Never world/player/UUID, auth data, module state, databases and signed packages. Verify restore on a separate host. Follow the reconciliation/rollback document for any writes since the last source snapshot.
- A dedicated canary Minecraft account authorized to test login on **target** and **public** HTTPS authentication endpoints. The POST request body is an owner-only file; the response must contain the precise canonical Minecraft UUID in `uuid`, `playerUuid`, or `id`. Use an actual login API—not a health endpoint that always returns a UUID. TLS host verification is mandatory, and redirects fail.
- A post-switch stage for `nl migrate gravit rehearse-local` with a real client executable, test probes and a real loopback RCON game server. The stage's `live-session.json` `clientArgs` must include the chosen public Minecraft address (`host:port`), not a direct private server address. Both canary login and RCON-observed Minecraft join must refer to the same UUID. **The operator must independently verify that the actual launcher arguments really connect through this public HAProxy entry point.** Presence of an argument substring is only a static guard against accidental direct-target tests.

## конфигурация

Create `/srv/never-cutover/config.json` as mode `0600`; make `/srv/never-cutover/journal` a mode `0700` directory on durable storage. Do **not** put access tokens or passwords in the config or command arguments. Replace all example values with verified production values.

```json
{
  "format": "never/gravit-production-cutover/v1",
  "runId": "run_12345678",
  "profileId": "main",
  "channel": "stable",
  "stageId": "stage_12345678",
  "releaseId": "release-abc",
  "expectedRevision": 1,
  "baselineRevision": 7,
  "targetDigest": "<64-character SHA-256 of signed Never manifest>",
  "sourceSnapshotSha256": "<64-character typed source snapshot SHA-256 from MIG10>",
  "inventorySha256": "<64-character migration inventory SHA-256>",
  "backend": "https://backend.example.org",
  "launcher": "/opt/never/launcher-cli",
  "launcherSha256": "<64-character executable SHA-256>",
  "proxySocket": "/run/haproxy/admin.sock",
  "routes": {
    "auth": {"backend": "auth-backend", "source": "gravit-auth", "target": "never-auth"},
    "game": {"backend": "game-backend", "source": "gravit-game", "target": "never-game"}
  },
  "drainSeconds": 240,
  "fenceReceipt": "/srv/never-cutover/fresh-fence-receipt.json",
  "gamePublicAddress": "play.example.org:25565",
  "postSwitchStage": "/srv/never-cutover/minecraft-canary-stage",
  "authCanary": {
    "url": "https://target-auth.example.org/login",
    "frontendUrl": "https://login.example.org/login",
    "method": "POST",
    "requestBodyFile": "/srv/never-cutover/auth-canary-request.json",
    "requestSha256": "<64-character SHA-256 of auth-canary-request.json>",
    "expectedPlayerUuid": "12345678-1234-1234-1234-123456789abc",
    "uuidJSONField": "uuid"
  }
}
```

`targetDigest` is the route's signed manifest digest, not the ZIP digest or source snapshot. `baselineRevision` is the old Never `channel_heads.revision`, not the cutover row's `expectedRevision`. The two fields are checked independently. The journal binds the complete configuration **bytes**; you cannot edit config and silently resume. The `fenceReceipt` path is specified **before** phase 1, but the receipt itself is produced **after** traffic has been drained and closed. It must be a **fresh** verified receipt with the same run/profile/channel/stage and typed source snapshot digest.

## Двухэтапное выполнение

On the operator host, set `LAUNCHER_TOKEN` in the secure process environment (never include it in shell history). Keep `config.json` unchanged throughout these steps.

**Phase 1 — stop new connections and drain existing ones**:

```sh
python3 tools/gravit-port/production_cutover_04911.py prepare \
  --config /srv/never-cutover/config.json \
  --journal-dir /srv/never-cutover/journal --confirm run_12345678
```

The tool requires a still-staged, matching PostgreSQL route; validates the exact running HAProxy backends and target state; issues real `set server BACKEND/SOURCE state drain` commands; waits until both sources show zero active sessions (`scur`); then moves **all four** source/target servers to `MAINT`. It durably records `traffic_fenced` and the HAProxy PID. If sessions do not drain, it attempts to force `MAINT` for both ingress backends; this **can interrupt** still-active players. If HAProxy cannot be reached, the operator must independently close firewall/proxy ingress and inspect all frontend routes before proceeding.

**Between phases — stop Gravit, take fresh source snapshot, verify fence**:

On the actual Gravit source host execute the existing `nl migrate gravit fence-source`, export a new *consistent* source snapshot taken after writers have stopped, and execute `nl migrate gravit verify-source-fence` as specified in [gravit-cutover-rollback.md](gravit-cutover-rollback.md). Place the resulting receipt at the exact `fenceReceipt` path in the already-immutable config. Finish before the receipt expires (10 minutes; stop event 15 minutes). Verify all other independent source-side writers externally; the receipt only proves the named systemd unit and snapshot. Avoid a long gap between phases.

**Phase 2 — activate real PostgreSQL route, target login and Minecraft traffic**:

```sh
python3 tools/gravit-port/production_cutover_04911.py activate \
  --config /srv/never-cutover/config.json \
  --journal-dir /srv/never-cutover/journal --confirm run_12345678
```

The tool requires unchanged HAProxy process identity and both public backends still `MAINT`; verifies the same staged route, source-fence receipt and direct target login with the expected UUID; invokes `nl migrate gravit cutover-activate` (Backend verifies fresh MFA, signed release, PostgreSQL transaction, MIG10 prerequisites and source fence); **re-reads** the route after the response; enables only the two target HAProxy servers; verifies they are `UP` and the sources remain `MAINT`; checks real login **through the public HTTPS ingress**; launches the post-switch Minecraft canary with `rehearse-local` and checks RCON-observed join + seven required probes and UUID; then rechecks the Backend route, HAProxy state and PID. `complete` is a local operational record, **not** an independent GA attestation.

Read local status without changing any route:

```sh
python3 tools/gravit-port/production_cutover_04911.py status \
  --config /srv/never-cutover/config.json --journal-dir /srv/never-cutover/journal
```

**On partial failure:** preserve the protected journal and all CLI outputs; stop all public ingress, check `cutover-list` and PostgreSQL `channel_heads` directly, then reconcile whether the DB activation committed. A failed activation may have committed even if the client timed out; no automatic retry is allowed. `blocked` is **never** resumed by calling `activate` again. After any successful PostgreSQL activation, do not unmask Gravit/replay old worlds without a **new reconciliation and rollback plan**; see [gravit-cutover-rollback.md](gravit-cutover-rollback.md). 

**HAProxy reload/reboot limitation:** runtime socket states are **not** durable HAProxy configuration. No HAProxy reload, worker replacement, deployment or auto-restart is permitted during this cutover; the tool detects PID changes across its two phases. Before ending the maintenance window, the operator must persist the *new target-only* routing configuration (and remove old source servers) using their own production HAProxy configuration management and validate a reload with separate ingress E2E. A reload after this script exits is **not** automatically protected; without that permanent configuration update old traffic can reopen. Alternative frontends/DNS/load balancers also require separate acceptance. This is a hard blocker for declaring production cutover completed.

## Подтверждения и ограничения

The audit directory contains route-before/pre-activate/activation/after/final JSON, post-switch Minecraft report, non-overwriting journal and a lock. Files are mode `0600`, directory `0700`. No bearer token, canary password or auth response is written to evidence. A second `prepare` in the same directory is rejected. The tool does not update Minecraft world files, migrate database writers, move player inventories, modify DNS, generate release signatures or certify HAProxy persistence, and should not be run on a real project until the staging exercise, external fencing and recovery procedures are proven.

**Local regression:** `python3 -m unittest discover -s tools/gravit-port -p 'test_production_cutover_04911.py' -v`. This uses an actual Unix-domain socket and real CLI subprocess invocations with test doubles for HAProxy/Backend, not production infrastructure. An actual HAProxy/PostgreSQL/Minecraft, signed release, Microsoft account and independent operator are still required for acceptance.

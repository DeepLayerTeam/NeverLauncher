# 0.44.7 — репетиция настоящей миграции Minecraft (MIG10)

The operator runs `nl migrate gravit rehearse` **on an isolated, disposable staging machine** that has a full Never client and a Minecraft Java server already running. The CLI checks an actual foreground client process and a new multiplayer join observed by the staging server through an authenticated loopback RCON connection. It **does not** run downloaded Gravit JARs, grant production permission or switch release channels.

## Set up and run

1. Create an isolated stage with `.migration-stage.json`, `source-snapshot.json`, `target-snapshot.json` and seven **real test** executables (`probes/{launch,login,join,skins,loader,optional,admin}`) according to the existing MIG10 format. Source and target snapshots must come from actual isolated world, inventory, permission, economy, texture and optional-preset exports; do not type synthetic digests. Use a *test* Minecraft account. Only a successful live join does **not** establish licensing, session validity, visual rendering, permissions or worlds; the separate probes remain necessary.
2. Start the migrated **test** Java server locally with RCON bound to `127.0.0.1`, `enable-rcon=true`, `broadcast-rcon-to-ops=false`, a strong unique password, and an RCON version supporting `/list uuids`. Do not expose the RCON port on a public interface, forward it to a production host or reuse production credentials. The player must be **offline** before the rehearsal starts.
3. Place an operator-authored **foreground** client launcher in the stage, e.g. `bin/start-client`, mode `0700`. This should start the real Never Desktop/Runtime → Java Minecraft process and **remain running** until exit. A script that exits after spawning a child will fail. The CLI launches it directly (no shell substitution) and observes its continued activity. Never use a dummy script that just returns success.
4. Store the staging password in a stage-local file such as `rcon-password` (mode `0600`), and create stage-local `live-session.json` (mode `0600`):

```json
{
  "clientPath": "bin/start-client",
  "clientArgs": [],
  "playerName": "StagingPlayer",
  "playerUuid": "12345678-1234-1234-1234-123456789abc",
  "rconAddress": "127.0.0.1:25575",
  "rconPasswordFile": "rcon-password",
  "timeoutSeconds": 300
}
```

The `playerUuid` must exist in `source-snapshot.json` and in the imported MIG04 UUID mapping. The `playerName` must match the real in-game username. Keep access tokens out of arguments and configuration: the foreground launcher should use the platform's normal protected credential store. A separate staging server or SSH tunnel that terminates **on loopback** can be used only when isolated from production; an arbitrary public RCON hostname is rejected.

```bash
nl migrate gravit rehearse \
  --run '<migration-run-id>' \
  --stage '/srv/isolated-migration-stage' \
  --inventory-sha256 '<MIG03-inventory-manifest-sha256>' \
  --backend 'https://test-never-backend.example' \
  --token '<short-lived-operator-token>' \
  --output '/srv/operator-private/rehearsal-result.json'
```

**Measured observations:** before launch, the CLI authenticates to the local Java server and verifies the target name/UUID is offline; then starts the foreground client and polls `list uuids` until that name/UUID pair appears. After a hold it checks again, while requiring the client process to remain alive. It repeats the live check after the independent probes and after the final target snapshot was read. Authentication failures, premature client exit, mismatched UUID, timeout, unavailable RCON, remote RCON destinations or a player already online make the operation fail. Raw process logs, RCON passwords and arguments are not persisted in the report; only hashes and join timestamps are sent. This is a **staging operator witness**, not tamperproof cryptographic proof: a malicious stage operator or substituted server can still falsify observations.

**Backend behavior:** the backend independently checks `liveSession` digests, source/target UUID consistency, join timeline, successful login and join probes, world/inventory/permissions/economy/skin comparisons, MIG03–MIG08 database receipts, and report idempotency before it can set `ready=true`. Legacy synthetic seven-probe reports without `liveSession` are now `ready=false`. A successful rehearsal **never** sets `cutoverAllowed`; MIG11 remains separate.

**Coverage boundaries:** this live witness uses Java Edition `/list uuids` and a local server with RCON, on a host able to execute the staged client. Actual macOS/Windows runtime and non-RCON server setups need a separately verified operator environment, not a presumed success. This version does not ship a Minecraft binary or real credentials and has not been tested in a real Minecraft session in the local development environment. To accept a real migrated project, run the full rehearsal on the actual isolated deployment with actual test accounts, assets, loader and bridge adapters. Existing probe scripts must contain meaningful independent checks for skin rendering, optional selection, login, admin privileges and state preservation. Recording a fake `passed:true` is not valid evidence.

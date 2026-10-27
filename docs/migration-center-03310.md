# NeverLauncher 0.33.10 — Isolated Migration Rehearsal (MIG10)

## Execution boundary

The API **never** starts arbitrary commands, a Minecraft launcher, a Gravit JAR or a live game server. The operator provisions a separate, dedicated isolated VM/container with distinct databases, disk copies, network, accounts and service credentials. The CLI runs probes exclusively on that operator-owned host; its staging marker is an explicit assertion, **not technical proof of isolation**. Do not run it on production infrastructure.

The rehearsal is **not** cutover approval. It verifies staged content and player-data snapshots, executes seven real stage-side test programs, obtains SHA-256 evidence for each, and sends the result for transactional cross-check against MIG03–MIG08. Any missing prerequisite or failed test blocks readiness. Backend responses always carry `cutoverAllowed=false`.

## Stage directory

Create a private absolute directory, for example `/srv/staging-rehearsal`, on the isolated host:

- `.never-migration-stage.json`: `{"format":"never/migration-stage/v1","runId":"<run>","stageId":"<unique-random-16+-chars>","isolated":true}`. Generate a fresh stage ID for every rerun after a changed result.
- `source-snapshot.json` and `target-snapshot.json`: snapshots exported **independently** from actual source and stage. Each has `worldSha256`, `loader`, `optionalPresetSha256`, `players`. Each player has `sourceId` (canonical `fileauth:<sourceId>` or `sql:<sourceId>` matching MIG04), `uuid`, `inventorySha256`, `permissionsSha256`, `economy` (exact decimal string), `skinSha256`, `admin`. Include every account in MIG04, not a curated subset. Capture the source snapshot while source writers are quiesced and the target snapshot **after the live probes**, without account secrets.
- `probes/launch`, `probes/login`, `probes/join`, `probes/skins`, `probes/loader`, `probes/optional`, `probes/admin`: executable **real** integration tests supplied for the specific Minecraft/loader/plugin environment. These must launch/validate the migrated client, authenticate with fresh Never trust, join the isolated Minecraft server, check expected UUID and skin, loader, optional preset and administrative role. Generic pass-only scripts are not sufficient evidence. Execute no production jobs or external auth services.
- Each probe exits `0` on successful execution and writes a single JSON object on stdout: `{"passed":true,"uuid":"<observed-player-uuid>","evidenceFile":"evidence/login","detail":"..."}`. An evidence file under the stage root must contain actual redacted test observations/logs. `login` and `join` must report the UUID actually seen by the server. The CLI hashes the file itself; stdout-supplied digests are not trusted. Any free-text detail is discarded rather than stored. No credentials, device private keys, tokens or raw full logs in these files.

The CLI invokes probes without a shell, with a 90-second timeout and minimal environment. This **does not provide a container sandbox**: the host operator is responsible for OS-level filesystem and network isolation. Avoid exposing production paths, mounts, key material or endpoints to stage programs.

## Execute

```
# Export NEVERLAUNCHER_TOKEN from your secrets manager before running.
nl migrate gravit rehearse \
  --run <migration-run-id> \
  --stage /srv/staging-rehearsal \
  --inventory-sha256 <MIG03-manifest-sha256> \
  --backend https://never-admin.example \
  --output /secure/path/rehearsal-result.json
```

Submitting requires fresh MFA and project-scoped management authorization. The CLI only accepts HTTPS or an explicit loopback IP backend. Results are persisted in PostgreSQL in `migration_rehearsals_03310`. Retries with the same stage ID must reproduce the same evidence; re-rehearsal with changed evidence requires a new stage ID. `GET /api/v1/admin/migration-runs/{runId}/rehearsal` returns the most recent report.

## Guardrails and limitations

- No tests are silently marked passed. Missing/failed `launch`, `login`, `join`, `skins`, `loader`, `optional`, `admin` probes block readiness.
- UUID, world snapshot hash, inventory, permissions, economy, skins, loader, optional presets and admin flags must be equal in source/stage exports. Mismatches are blocking.
- The server recomputes all checks and binds source accounts to the durable MIG04 identity map. MIG05 account import, MIG06 reset, MIG07 staged content and MIG08 module review are mandatory prerequisites.
- External probe output is **operator-supplied evidence**, not cryptographic attestation of actual Minecraft gameplay. Independent, observable end-to-end tests are mandatory for production promotion. This release does not automate provisioning of isolated Minecraft/SQL infrastructure, generate test users, or perform cutover/rollback.
- PostgreSQL integration tests require an isolated test DB. The code must pass CI with Go 1.27.3 before the release is considered production-certified.

# NeverLauncher 0.49.12 — эксплуатационный откат переключения с Gravit

**Scope:** one migrated `runId/profileId/channel`, on a dedicated local HAProxy process and a systemd-controlled pair of Gravit/Never writer groups. This is runnable operator code; it is **not** a substitute for independently proven production recovery. It reuses the existing PostgreSQL transactional `rollback-plan` / `rollback-commit` APIs. It must not be used to imply that overwriting an old Minecraft world restores new data. No automatic source restart or traffic reopen is provided.

## Обязательные предварительные условия

- Use the **unchanged** mode-0600 0.49.11 cutover JSON and 0700 cutover journal containing the real post-activation state. Verify the live route, not just the local journal. A *new*, mode-0600 rollback JSON is bound to the exact SHA-256 bytes of that cutover JSON.
- The operator must execute from a host with real `systemctl show` access to **all** the listed source/target units and the local HAProxy admin Unix socket. This tool does **not** stop/mask processes, force-close unrelated ingress, fence other hosts, stop database writers, or inspect Kubernetes/Docker processes. If any such writer exists, its separately verified fencing is an additional hard prerequisite. Merely listing one systemd unit does not prove global quiescence.
- Export fresh, consistent Gravit/Never snapshots from actual quiesced worlds and user/plugin data in the `gravitrehearsal.Snapshot` JSON format. All exports are *owner-only (0600)* files. The source must still match the MIG10 baseline unless a separately completed and independently validated reconciliation provides a new source export matching the changed Never data. **The snapshot report is not a backup and does not copy worlds or plugin SQL databases.**
- Verify independent backups and test restoring them on another machine. A changed inventory, UUID, privileges, economy, world hash or other material state is not safe to silently discard. The Backend compares domain fields and is the authority for whether a rollback plan is ready. For a reconciliation, the operator must supply the existing Backend `reconciliationEvidenceSha256`, not an invented value. This local tool additionally requires the current/source exports to agree exactly after reconciliation.
- The old baseline **NeverLauncher release** must still exist, be signed and pass its runtime gates. A PostgreSQL rollback changes the Never release channel head; it does **not** switch a Gravit proxy, restore worlds or reissue legacy sessions. A stable-channel rollback still needs the existing one-time stable gate token.

## восстановление конфигурация

`/srv/never-cutover/rollback.json` (mode 0600), created and sealed **after** the unchanged cutover JSON has been chosen:

```json
{
  "format": "never/gravit-operational-rollback/v1",
  "runId": "run_12345678",
  "profileId": "main",
  "channel": "stable",
  "cutoverConfigSha256": "<64 lowercase hex digits of exact original config bytes>",
  "units": {
    "source": ["gravit-launchserver.service", "gravit-minecraft.service"],
    "target": ["never-launcher.service", "never-minecraft.service"]
  },
  "currentSnapshot": "/srv/never-cutover/snapshots/never-after-fence.json",
  "sourceSnapshot": "/srv/never-cutover/snapshots/gravit-after-restore.json"
}
```

If source was reconciled to new Never data, add `"reconciliationEvidenceSha256": "..."` only after completing and independently verifying the real data reconciliation. Never add it merely to bypass mismatches. Both world and all player records must match, and the Backend must confirm the reconciled plan. There are no bearer tokens or passwords in this JSON; set `LAUNCHER_TOKEN` in the protected process environment. `cutoverConfigSha256` must be an actual SHA-256 of the unmodified cutover JSON, not a placeholder.

## Порядок действий

**1. Fence traffic:** stop new maintenance-window sessions on *all* ingress paths. The first command actively issues HAProxy `MAINT` for auth and game sources and targets, checks the same PID and writes a durable phase journal. It requires the original Backend route still active. This can disconnect players. On any uncertainty keep the firewall/HAProxy closed.

```sh
python3 tools/gravit-port/operational_rollback_04912.py fence \
  --cutover-config /srv/never-cutover/config.json \
  --rollback-config /srv/never-cutover/rollback.json \
  --journal-dir /srv/never-cutover/journal --confirm run_12345678
```

**2. Stop and mask all independent source/target writers.** Only after real stop confirmations export NEW, consistent source/Never JSON snapshots. The `plan` command re-reads every listed systemd unit, the live HAProxy process, the source baseline digest and the current PostgreSQL route. If Never data changed, it fails unless reconciliation is already complete. `plan` calls the Backend's actual rollback planner and requires `ready=true`, no blockers, correct mode and exact raw snapshot SHA-256.

```sh
python3 tools/gravit-port/operational_rollback_04912.py plan \
  --cutover-config /srv/never-cutover/config.json \
  --rollback-config /srv/never-cutover/rollback.json \
  --journal-dir /srv/never-cutover/journal --confirm run_12345678
```

**3. Export another independent NEW Never snapshot, after the plan** (a separate absolute path; bytes must still agree exactly). Complete the commit within the Backend's ten-minute approval window. The operator tool conservatively refuses plans aged nine minutes. `commit` checks both writer groups again, rechecks closed HAProxy, compares the fresh bytes and source export with the plan and executes existing `rollback-commit` with both writer fences. It then independently reads the stored rollback status and the rolled-back PostgreSQL route.

```sh
python3 tools/gravit-port/operational_rollback_04912.py commit \
  --cutover-config /srv/never-cutover/config.json \
  --rollback-config /srv/never-cutover/rollback.json \
  --journal-dir /srv/never-cutover/journal --confirm run_12345678 \
  --fresh-snapshot /srv/never-cutover/snapshots/never-second-export.json
```

If the commit is ambiguous due to timeout, the tool records `uncertain` and tries to close ingress. **Do not repeat `commit`.** Inspect PostgreSQL and use `reconcile` to read *only* authoritative Backend status/route. A result cannot be upgraded to success from a local process exit status alone.

```sh
python3 tools/gravit-port/operational_rollback_04912.py reconcile \
  --cutover-config /srv/never-cutover/config.json \
  --rollback-config /srv/never-cutover/rollback.json \
  --journal-dir /srv/never-cutover/journal --confirm run_12345678
```

`status` reads local phase only. Success is `committed_fenced`: **both ingress backends remain MAINT**. This is deliberate: the restored Never channel head is not a license to restart legacy Gravit writers or replay outdated worlds. An independent operator must verify data and auth, deliberately enable the intended serving deployment, persist the desired HAProxy configuration, perform real Minecraft authentication/join and test HAProxy reload/failover. No other frontend or load balancer is changed here.

## Восстановление файлов остановленного Minecraft (не работающей базы данных)

`cold_data_restore_04912.py` can seal an already **consistent offline backup directory** and restore its regular world/player/config files into a stopped directory. It rejects symlinks, hard-linked files, device nodes, duplicate/unsafe paths, changed sizes or hashes, and overlarge input. It copies files to a same-filesystem staging directory, verifies every SHA-256, then retains the previous target as `TARGET.before-RUN` while installing the replacement. Its durable journal supports `recover` after a kill during the two-rename window; no old directory is silently deleted.

```sh
python3 tools/gravit-port/cold_data_restore_04912.py seal \
  --source /srv/verified-backups/gravit-world \
  --manifest /srv/never-cutover/gravit-world-backup.json --run run_12345678

# Only AFTER the rollback ingress fence and after source and target writers
# are all stopped/masked. This restores files to the named cold directory.
python3 tools/gravit-port/cold_data_restore_04912.py restore \
  --source /srv/verified-backups/gravit-world \
  --target /srv/gravit/minecraft \
  --manifest /srv/never-cutover/gravit-world-backup.json \
  --cutover-config /srv/never-cutover/config.json \
  --rollback-config /srv/never-cutover/rollback.json \
  --journal-dir /srv/never-cutover/journal --run run_12345678

# If killed mid-rename, with the writers and ingress still fenced:
python3 tools/gravit-port/cold_data_restore_04912.py recover \
  --source /srv/verified-backups/gravit-world \
  --target /srv/gravit/minecraft \
  --manifest /srv/never-cutover/gravit-world-backup.json \
  --cutover-config /srv/never-cutover/config.json \
  --rollback-config /srv/never-cutover/rollback.json \
  --journal-dir /srv/never-cutover/journal --run run_12345678
```

A sealed backup is **not automatically newer than the Never world**. If Never accepted new writes, first carry those world/player/economy/permission/plugin changes into the offline source and independently verify the resulting source snapshot; otherwise `rollback-plan` must block. File restore intentionally does not restore PostgreSQL or MySQL/MariaDB, payment/economy plugins, external object stores or Minecraft sessions. Those need their own independently tested transactional/application-consistent restore and reconciliation. Do not restart writers until every such state has been reconciled.

## Тесты и ограничения GA

Run `python3 -m unittest -v test_operational_rollback_04912 test_cold_data_restore_04912 test_production_cutover_04911` from `tools/gravit-port`.

These are local tests of real subprocess calls, Unix socket messages, atomic file replacement and negative failures **against controlled test services**, not actual production PostgreSQL/Minecraft/systemd. Before declaring 0.49.12 GA, independently prove real-world game preservation, auth/UUID equality, plugin and DB recovery, multi-host fencing, signed native packages, failure injection across process/network boundaries, source-service restart, persistent proxy reload and Minecraft join on exact final assets. Missing receipts or independent attestations remain `BLOCKED`.

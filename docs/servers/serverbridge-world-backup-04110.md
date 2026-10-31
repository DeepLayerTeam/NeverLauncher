# NeverLauncher 0.41.10 — verified world backup and recovery

The CLI **does not** perform a live `save-all` snapshot. A consistent snapshot is accepted only after Host Supervisor has confirmed a graceful Minecraft `stop` and the JVM has exited. Hosts that run outside the managed supervisor are not automatically discoverable: an untracked Minecraft process must be stopped separately and its exit established by the operator.

## Stopped-world snapshot

```bash
nl server-bridge host world-backup create --server-root /srv/minecraft --backup-root /srv/mc-backups --consistency stop
nl server-bridge host world-backup list --server-root /srv/minecraft --backup-root /srv/mc-backups
nl server-bridge host world-backup verify --server-root /srv/minecraft --backup-root /srv/mc-backups --id BACKUP_ID
```

The host-level `world-maintenance.gate` prevents a new JVM spawn during snapshot creation, including the supervisor's crash-loop retry path. Only the backup agent owning the gate can release it. After a crash, the gate persists so that neither an automatic start nor a second backup can overwrite the uncertain state.

To inspect a crashed gate read `.neverlauncher/server-bridge/host/world-maintenance.gate/owner.json`, Host Supervisor `runtime.json`, and the OS process identities. Only once the former owner, supervisor and game JVM are confirmed gone may the operator run:

```bash
nl server-bridge host world-backup gate-recover --server-root /srv/minecraft --confirm stale-gate
```

A missing/malformed owner is intentionally not cleared automatically. An active child process prevents recovery. If a backup process was interrupted, verify the last complete backup ID and inspect partial directories manually. Never delete active locks to accelerate deployment.

## Restore into an isolated root

```bash
nl server-bridge host world-backup restore --server-root /srv/minecraft --backup-root /srv/mc-backups --id BACKUP_ID --confirm BACKUP_ID --destination /srv/minecraft-recovered
```

The destination must not exist and cannot overlap the live server or backup store. Files are hashed again while copied, staged privately, and atomically published only after verification. A second restore to the same destination fails; no automatic JVM restart occurs. After verifying UUID playerdata, region files, and plugin state, use a **separate maintenance/deployment procedure** to switch your managed server to the restored root. Do not copy a partial restore over a running server. Do not mistake isolated file restore for evidence that a real Minecraft server can load the world; use the Paper E2E for that test.

## Reproducible integration checks

```bash
cd cli && go test -race ./cmd/neverlauncher -run 'TestWorldBackup' -count=1
cd cli && go build -o /tmp/nl ./cmd/neverlauncher
python3 scripts/test/world-backup-real-java-04110.py --cli /tmp/nl
python3 scripts/test/world-backup-host-e2e-02810.py --cli /tmp/nl
```

The OpenJDK test executes a **real JVM process**, but its minimal Java program is a fixture rather than an upstream Minecraft JAR. The repository's `e2e/scripts/verify-real-world-backup-0290.py` requires Docker, a real Paper container, a real player join, a stored player UUID, and persisted plugin data. That live test must pass before calling upstream Paper recovery fully certified.

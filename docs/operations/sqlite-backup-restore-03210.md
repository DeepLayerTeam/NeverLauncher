# Launcher 0.32.10 — DEP06 SQLite Backup & Restore

## Support boundary

The SQLite durable store and Core CLI are operational code. The main HTTP
Repository still uses PostgreSQL in this release. This functionality does not
replace PostgreSQL `pg_dump`, S3/local storage backups, Redis/coordination
backups, or a complete server recovery plan.

Use Linux on verified **ext4, XFS or Btrfs** with a private service-owned
**0700** DB directory and **0600** DB and backup files. SQLite binaries and
pinned driver must be available. Deployments on NFS, SMB, overlayfs or tmpfs
fail closed. Snapshots contain auth and other sensitive state; protect the
backup directory as strongly as the live DB, and encrypt copies off-host.

## Back up a running SQLite database

```sh
launcher-sqlite backup \
  --db /var/lib/launcher/sqlite/state.db \
  --backup /var/lib/launcher/backups/state-2026-10-27.db
launcher-sqlite backup-verify \
  --backup /var/lib/launcher/backups/state-2026-10-27.db
```

The snapshot reads committed pages from the live WAL using a **separate SQLite
read-only connection** and `VACUUM INTO ?`, then fsyncs the output and its
parent directory. It checks `integrity_check`, `foreign_key_check`, and schema
version, records the file size and SHA-256 in an exclusive-created sidecar
`.db.json`, and publishes the snapshot without overwriting previous files.
It does not truncate the live WAL. The sidecar is not an Ed25519 signature:
SHA-256 here detects accidental or unsynchronized changes, not attacker
modification of both the backup and its manifest.

## Mandatory pre-upgrade validation

```sh
launcher-sqlite pre-upgrade \
  --db /var/lib/launcher/sqlite/state.db \
  --backup /var/lib/launcher/backups/preupgrade-2026-10-27.db
```

This operation fails closed unless the backup succeeds, checksum and SQLite
integrity/foreign keys pass, and the snapshot can be restored to a temporary,
private location and reopened with a passing **SQLite Core Repository Check**.
The temporary restored copy is removed and the verified snapshot is retained.
Additionally, **automatic SQLite Core schema migration** from 322–325 to 326
now performs a verified backup and offline restore proof in a protected
`pre-upgrade-backups/` subdirectory **before DDL**. A failed proof blocks the
migration. New blank database initialization is not an upgrade.

IMPORTANT: The current release's general installer does not implement an
in-place production fleet upgrade or an automatic HTTP SQLite database
migration. Use the `pre-upgrade` gate in your deployment runbook for upgrades
that are not performed through `sqlitecore.Open`.

## Restore (offline only)

Stop Launcher (all processes using this DB) first. A running Launcher
holds an exclusive owner lock; restore refuses to proceed. SQLite `-wal`,
`-shm` and `-journal` sidecars are **not automatically deleted**, even if they
were left by a crash. Restart/repair and checkpoint the original DB, shut it
down cleanly, and then restore. Never discard a WAL file containing uncommitted
recovery state as part of an automated restore.

```sh
launcher-sqlite restore \
  --backup /var/lib/launcher/backups/preupgrade-2026-10-27.db \
  --db /var/lib/launcher/sqlite/state.db --replace
launcher-sqlite core-status \
  --db /var/lib/launcher/sqlite/state.db
```

`--replace` must be explicit when a target exists. Restore takes the same
owner lock as normal SQLite startup, checks the snapshot twice, copies to a
private staged file with fsync, rechecks the copy and SQLite constraints,
retains the old database as a `state.db.pre-restore-*` hardlink, and atomically
renames the new DB into place. Keep the rollback copy until real application
smoke tests have passed. This protocol assumes all writers observe the
Launcher owner lock; it does not forcibly terminate unrelated clients
which bypass that lock.

No backup tool can guarantee preservation of writes made **after** its
snapshot. At recovery, inspect joined/auth sessions, one-time tickets,
revocations, release heads, bridge commands and audit; account for RPO and
post-snapshot state before admitting clients.

## Disaster recovery validation

Test on the same supported filesystem and runtime version: snapshot a live
WAL DB during writes, restore to a separate directory, check Core invariants,
check exact project/user/UUID data, test a cancelled/tampered backup, and
verify that a second process cannot restore while the owner is running.
The CI workflow `sqlite-backup-03210.yml` covers these gates.

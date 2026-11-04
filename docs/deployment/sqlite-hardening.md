# SQLite deployment hardening — NeverLauncher 0.47.1

SQLite HTTP (`http.sqlite`), coordinator (`coordinator.sqlite`) and independent Core all use the single-owner `sqlitedurable` store. The hardening changes in 0.47.1 add no automatic destructive repair. A corrupt or structurally incompatible database must be examined and restored from an independently verified backup; NeverLauncher must not start with empty defaults or silently rebuild its state.

## Before deploying

1. Stop the Backend or otherwise ensure no conflicting process owns a SQLite store. Place databases on a service-owned, private (`0700`) ext4, XFS or Btrfs local directory. Do not place a SQLite WAL database on NFS, SMB, overlayfs or tmpfs.
2. Make and verify separate consistent online backups of the HTTP, coordinator and Core DBs using the existing SQLite backup facility. Do not copy a live `.db` file without its WAL. Retain original backups and `.json` manifests outside the upgrade workspace.
3. Perform a full backup restore rehearsal before upgrading, including project/profile, owners and rate-limiter/lease state. Upgrade in a maintenance window and keep previous binaries and backup snapshots available.
4. On startup, the store checks `PRAGMA integrity_check`, foreign keys and WAL mode and validates private SQLite sidecars. HTTP rejects malformed JSON state even with a recomputed checksum. Coordinator rejects drift from its declared schema and Core rejects arbitrary unversioned schemas.
5. If startup fails, **do not delete** `-wal`, `-shm` or the DB itself, do not reset `user_version` and do not apply `CREATE TABLE` by hand. Stop all owners, preserve the full directory and restore from an independently verified backup after determining the failure cause.

## Checkpoint, rollback and failure boundaries

`Store.Checkpoint` now uses `wal_checkpoint(TRUNCATE)`, returning an error when a reader blocks completion instead of signaling maintenance success with outstanding WAL frames. Checkpointing is **not** a backup. A failed `COMMIT` may have completed in SQLite; the store becomes unusable until it has been closed and its last operation has been reconciled after reopen. A rollback failure poisons the store unless the underlying SQL connection has already been discarded by `database/sql`.

HTTP Repository Health verifies sequence, digest and the complete snapshot envelope, and becomes fail-closed after detecting inconsistency. New installations initialize empty state only when the database has no existing application tables. Existing databases with a missing HTTP snapshot never automatically reset to zero data.

## CI / independent acceptance

On a host with Go 1.27.3, the pinned SQLite module and an ext4/XFS/Btrfs working directory, run:

```bash
cd services/api
LAUNCHER_SQLITE_TEST_ROOT=/path/to/private/sqlite-test-dir LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS=1 go test -count=1 ./internal/sqlitedurable ./internal/sqlitecoord ./internal/sqlitecore ./internal/repository ./internal/sqliteacceptance
```

Use a scratch test directory (`0700`, owned by the test user). The three-DB crash regression commits data to HTTP, Core and Coordinator, kills its child with `os.Exit(71)` without closing any DB, and verifies the acknowledged state after a new process takes ownership. Run these tests on the actual deployment filesystem and with the same pinned SQLite engine. Also test live OS-level termination, low-disk-space, storage I/O failures, competing readers, backup/restore and service readiness on a dedicated acceptance host. This source patch is not proof that those production checks have already run.

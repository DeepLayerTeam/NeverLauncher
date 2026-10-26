# 0.32.1 — SQLite Driver, WAL, durable commits (DEP00)

**Scope:** A physically durable SQLite transactional component and preflight command.
This is **not** a NeverLauncher SQLite application backend. Do not set
`NEVERLAUNCHER_REPOSITORY_DRIVER=sqlite` in production until DEP01–DEP03 parity
has been implemented, tested, and reviewed. The HTTP API continues to require PostgreSQL.

## Pinned build inputs

- Go toolchain: **1.27.3** (backend Docker build stage).
- `modernc.org/sqlite` **v1.61.0**; compiled-in SQLite **3.54.1**.
- `modernc.org/libc` **v1.79.0** (same as the driver upstream go.mod).
- Supported SQLite host for DEP00: **Linux with local ext4, XFS, or Btrfs**, effective user owns private `0700` DB directory. All other mounts including NFS/CIFS, overlay, tmpfs and foreign OSes fail closed until certified.
- The local database is private (0600), parents must contain no symlinks, and single-owner fencing uses a persistent `.owner.lock` flock file. Do not unlink the lock file while the store runs. A second process is refused while the lock inode and path remain unchanged; do not rename or replace the database directory while a backend is running.

## Build/verification

```sh
cd services/api
go mod download
go mod tidy
# Commit the resulting go.sum after retrieving upstream signed checksums.
go test -race -count=1 ./internal/sqlitedurable ./cmd/neverlauncher-sqlite
go build -trimpath -o neverlauncher-sqlite ./cmd/neverlauncher-sqlite
chmod 0700 /var/lib/neverlauncher/sqlite
./neverlauncher-sqlite probe --db /var/lib/neverlauncher/sqlite/state.db
./neverlauncher-sqlite verify --db /var/lib/neverlauncher/sqlite/state.db
```

The probe actually creates a test table, commits a nonce challenge, closes and
reopens the database, reads the committed data from a new connection, removes
the challenge, and queries WAL checkpoint progress. It does not verify that
kernel, disk-controller, and physical storage all honor flush barriers. This
requires a certified deployment environment and crash/power-loss testing.

## Guarantees and caveats

- Both reader and writer PRAGMAs are installed via driver DSNs on every physical
  connection. A successful writer opening verifies WAL, FK enforcement, FULL
  synchronization, timeout, trusted schema, engine version and compile options.
- `Write` uses `BEGIN IMMEDIATE`, one writer connection, context-aware statements,
  rollback with a fresh timeout on callback errors/cancellation, and successful
  `COMMIT` as the only success path. Unknown commit outcome is explicitly returned
  as `ErrCommitUnknown` (caller must reconcile using immutable operation ID).
- Busy timeout is bounded at 1ms–60s. Bounded read connections, checkpoint
  progress, and lock contention can be observed without in-memory success
  fallbacks. `Checkpoint` is not a backup.
- This component has no business-domain tables, no auth/session replay logic, no
  durable coordinator, no online backup and no SQLite-to-PostgreSQL migration.
  These are separate DEP01–DEP10 deliverables.

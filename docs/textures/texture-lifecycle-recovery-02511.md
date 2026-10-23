# NeverLauncher 0.25.11 — Texture Lifecycle & Recovery

This release makes the existing texture maintenance CLI safe against multiple
GC processes and concurrent backup/restore operations. It operates on the real
PostgreSQL rows and the configured local or S3 texture storage, not a manifest
or an independent database.

## Runbook

1. Stop previous texture-maintenance workers before upgrading. Old 0.25.3–0.25.10 GC workers do not understand backup pins or fenced leases; **never run old and new workers concurrently**. Apply database migration `0074_texture_lifecycle_recovery_02511.sql` using
   the normal NeverLauncher migration command **before** running the updated
   maintenance CLI. Keep `texture_blobs` and storage snapshots together in your
   disaster-recovery plan; a PNG-only snapshot does not restore assignments.
2. Set `NEVERLAUNCHER_DATABASE_DSN` and `NEVERLAUNCHER_STORAGE_DRIVER=local|s3`
   with the same storage configuration as API. Use isolated operator credentials.
3. Verify objects: `go run ./cmd/texture-maintenance-0253 --command=verify --report=texture-integrity.json`.
   The command streams and hashes complete blobs, validates their lengths and
   SHA-256 against PostgreSQL, emits one result per digest and returns non-zero
   if any object is unavailable/corrupt. The report is created mode `0600` and
   will not overwrite an existing report.
4. Backup: `go run ./cmd/texture-maintenance-0253 --command=backup --backup=/backups/textures-YYYYMMDD`.
   The inventory is pinned transactionally against GC for up to 45 minutes;
   the CLI has a 30-minute context deadline. A snapshot is published only after
   **all** files have been verified and fsynced. It cannot overwrite a prior snapshot.
5. Restore: restore a matching PostgreSQL backup first, then run
   `go run ./cmd/texture-maintenance-0253 --command=restore --backup=/backups/textures-YYYYMMDD`.
   Current DB inventory authorizes the restore. Full manifest and object hashes
   are verified before repair begins. Local repairs are now performed with an
   fsynced temporary file and atomic rename. S3 repairs require an ETag-matched
   conditional PUT and subsequent readback.
6. Garbage collect: `go run ./cmd/texture-maintenance-0253 --command=gc --limit=50`.
   Only objects older than seven days without assignments, saved items,
   project defaults, recent revisions or active snapshot pins are candidates.
   A unique token fences each claim (45-minute expiry). GC revalidates its token
   and storage object, uses S3 conditional `If-Match` deletion, then atomically
   deletes the PostgreSQL row with full reference checks. Failed object deletion
   releases only the requesting worker's lease; crashed leases can be reclaimed.

## Operational constraints

- The `verify` mode checks all `verified` objects. `staging` and quarantined
  objects are managed by GC and are not represented as a completed backup.
- Snapshot protection expires after 45 minutes. Do not bypass the maintenance
  CLI's 30-minute limit. If backups routinely exceed that time, increase both
  time limits coherently before scheduling unattended jobs.
- The S3 backend must support SigV4 requests and conditional DELETE with a
  strong ETag; otherwise garbage collection fails closed instead of risking
  deletion of another writer's object. Run this against your exact S3 provider.
- Never run backup and restore from a location writable by untrusted users.
  Backups include private PNGs. Restrict access and store copies offsite.
- GC deliberately refuses to delete corrupt S3 objects. Investigate and repair
  from a verified snapshot before retrying maintenance.
- PostgreSQL integration tests require a disposable PostgreSQL 17+ instance and
  `TEST_PG_DSN_02511`. CI starts an actual PostgreSQL service and executes the
  tests with the race detector. A full game-level compatibility certification
  remains a separate 0.25.12 gate.

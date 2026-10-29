# NeverLauncher 0.37.7 — verified SQLite ↔ PostgreSQL offline transfer

**Status: runnable offline transfer, not live backend cutover.** Importing rows into the `neverlauncher_sqlite_import_03211` schema or a complete minimal backup into `neverlauncher_minimal_transfer_0377` does **not** populate PostgreSQL HTTP Repository production tables. The current PostgreSQL `SQLRepository` cannot serve these imported schemas. Consequently `readyForBackendCutover` is always `false`, including for a successful import/export. No CLI flag promotes an unverified migration to production.

Run all operations on a local, operator-controlled, private filesystem, with an isolated PostgreSQL database. The PostgreSQL account must have permission to create a new schema and triggers. The transfer stores password hashes, secrets, signing keys, tokens, audit trails, and user data in PostgreSQL **unencrypted at the application layer**; apply transport encryption, full-disk encryption, strict role privileges, and backups. Never point the command at a shared or untrusted database.

## Complete minimal installation, including HTTP/Coordinator SQLite + project files

1. Stop API and every file writer. Acquire a consistent offline backup using the existing installer:

   ```sh
   python3 scripts/install/minimal-install.py backup --root /var/lib/neverlauncher-minimal --destination /private/backups/minimal-2026-10-29
   python3 scripts/install/minimal-install.py backup-verify --bundle /private/backups/minimal-2026-10-29
   ```

2. Set `NEVERLAUNCHER_POSTGRES_DSN` in the operator's environment (do not put secrets in command arguments). Using the compiled `neverlauncher-sqlite` binary:

   ```sh
   neverlauncher-sqlite minimal-to-postgres --bundle /private/backups/minimal-2026-10-29 --ack-no-backend-cutover
   neverlauncher-sqlite postgres-to-minimal --bundle /private/backups/reconstructed --ack-no-backend-cutover
   ```

3. Verify and restore the exported bundle **into a new, nonexistent directory**:

   ```sh
   python3 scripts/install/minimal-install.py backup-verify --bundle /private/backups/reconstructed
   python3 scripts/install/minimal-install.py restore --bundle /private/backups/reconstructed --target-root /var/lib/neverlauncher-restored
   ```

The transfer validates the SHA-256 and length of each file and chunk, checks both SQLite databases for logical/foreign-key corruption, and preserves original JSON manifests and byte-exact file data. The destination cannot be overwritten. A second import into the same transfer schema is rejected. User/role/device trust, nonce history, durable jobs, published heads and identity data remain in the original SQLite bytes, not a lossy reinterpreted data model.

## Independent SQLite Core schema 326 transfer

If working with an existing `sqlitecore` backup (created by `neverlauncher-sqlite backup`), the separate SQL row-preserving transfer supports:

```sh
neverlauncher-sqlite sqlite-to-postgres --backup /private/core-backup.db --ack-staging-only
neverlauncher-sqlite postgres-to-sqlite --backup /private/recovered-core.db --ack-no-backend-cutover
neverlauncher-sqlite backup-verify --backup /private/recovered-core.db
```

The `neverlauncher_sqlite_import_03211` schema includes immutable row mirrors and the original byte-exact SQLite backup in SHA-256-verified chunks. The reverse operation checks every mirrored table and row digest against the reconstructed SQLite snapshot and verifies Core invariants before publishing the restored file and its `.json` manifest. The original core migration bug that allowed `TRUNCATE` in its mirror is closed.

## Mandatory constraints

- Import is **additive** and transactionally rolls back on errors; it never truncates or edits live PostgreSQL application tables. PostgreSQL transactions with unknown commit outcomes must be reconciled before any retry.
- Import/export is **not** a conflict merge, active-session migration, credential reissuance, filesystem snapshot without stopping writers, HA migration or a PostgreSQL production backend switch.
- A true live SQLite → PostgreSQL → SQLite backend cutover still requires mapping and verifying every active HTTP Repository and runtime store, a service maintenance window, fencing, dual-mode application acceptance, and reverse failover tests. Do not claim this production gate passed based solely on the offline transfer.
- Required CI runs actual PostgreSQL and modernc SQLite integration tests, including import/reverse export, hash parity, immutable-table enforcement, missing/duplicate target rejection, and reconstruction of both SQLite databases plus binary files. The checked-in tests require the repository's Go toolchain and an isolated PostgreSQL fixture.

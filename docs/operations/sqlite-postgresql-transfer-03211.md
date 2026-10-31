# Launcher 0.32.11 — DEP07: SQLite → PostgreSQL staging transfer

## Important: no production cutover in this release

The SQLite Core v326 and the native PostgreSQL HTTP Repository have different
security/authentication, release, audit and lease schemas. Importing data by
matching table names would silently lose or reinterpret revocation state and
break Minecraft identity or one-use joins. **Version 0.32.11 implements the
transactional, checked data-transfer stage, NOT an operable PostgreSQL Backend
migration or a full DEP07 delivery. Do not shut down SQLite or route players
to the imported schema.** `readyForBackendCutover` is always `false`.

## Safe supported operation

1. Keep the SQLite service running and create a fresh online snapshot:

   ```sh
   launcher-sqlite backup --db /var/lib/launcher/state.db \
     --backup /var/lib/launcher/backups/dep07-03211.db
   launcher-sqlite backup-verify \
     --backup /var/lib/launcher/backups/dep07-03211.db
   ```

2. Provision a dedicated PostgreSQL database with a role allowed to create
   schemas. For remote connections require TLS certificate verification.
   Store the connection string securely in `NEVERLAUNCHER_POSTGRES_DSN` (never
   in CLI arguments, source control or logs).

3. Run (requires sufficient PostgreSQL space, local filesystem for SQLite
   restore validation and a deadline appropriate for the database size):

   ```sh
   launcher-sqlite sqlite-to-postgres \
     --backup /var/lib/launcher/backups/dep07-03211.db \
     --ack-staging-only --timeout 60m > dep07-transfer-report.json
   ```

4. Inspect the report and receipt in schema
   `launcher_sqlite_import_03211.migration_receipt`. The importer verifies
   the snapshot SHA-256 and `integrity_check`/`foreign_key_check`, restores an
   isolated copy to run SQLite Core application checks, then transfers every
   non-internal SQLite table to PostgreSQL as exactly typed SQL values.
   All copied rows are reread from PostgreSQL and compared using per-row and
   per-table SHA-256 digests, order, and row counts. Primary keys, nonpartial
   unique indexes and explicit foreign keys are validated before COMMIT.

## Properties

- **Atomic:** one PostgreSQL SERIALIZABLE transaction; no partially visible
  imported schema when copy or verification fails. Transaction-scoped advisory
  lock serializes importers; never overwrites a previous import.
- **Complete staging:** all SQLite Core 326 application tables and columns,
  including revoked token history, TOTP ciphertext, immutable Minecraft UUIDs,
  bridge nonces/tickets, package blobs, idempotency keys, leases and fencing
  high-water marks are preserved as-is. Timestamps remain signed nanosecond
  integers; no timezone precision conversion in staging.
- **Read-only after import:** triggers prevent INSERT/UPDATE/DELETE of copied
  rows; a receipt records the snapshot and all table digests.
- **Not a cutover:** native PostgreSQL Repository has different tables and
  authentication guarantees. Staging rows are not activated in that repository.
  The import is NOT a substitute for writing and proving adapters for auth,
  runtime coordination, signed join redemption and full release semantics.
- **No resume/overwrite:** a commit ambiguity must be resolved by checking for
  the schema/receipt. Repeating the command into an existing schema fails closed.
- **Rollback:** no live Backend changes are performed. To reverse the staging
  action, a database administrator can drop ONLY the dedicated import schema,
  after explicitly verifying no investigation/compliance need remains.

## Remaining DEP07 acceptance gates

- Translate every SQLite 326 state machine into the native PostgreSQL runtime
  schema and update the HTTP Repository to use it; do not rely on staging tables.
- Validate replay protection, revoked sessions, MFA, identity UUID stability,
  signed join redemption, worker fencing, packages and audit after conversion.
- Perform a frozen-write final delta/cutover with actual Desktop/Guard/Runtime
  clients using the same user and Minecraft UUID, followed by rollback rehearsal.
- Pass PostgreSQL and SQLite integration tests on supported native filesystem
  and Go toolchain, and provide an operator-approved cutover procedure.

The environment that produced this artifact did not have PostgreSQL server,
Go 1.27.3 or the pinned SQLite driver available; CI must run the full tests.

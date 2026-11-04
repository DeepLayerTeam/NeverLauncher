# NeverLauncher 0.47.3 — SQLite Core → SQLRepository (live data)

## Supported input and safety boundary

The CLI consumes an immutable, independently verified SQLite **Core 327** backup
created via `launcher-sqlite backup`, with its matching `.json` manifest. It first
runs the existing `sqlitepg.Import` into the immutable staging namespace and
then materializes compatible rows in the **real** SQLRepository tables in one
SERIALIZABLE PostgreSQL transaction. It does not use a memory or HTTP fallback.

An empty PostgreSQL database with the **complete** embedded `dbmigrate.Apply`
SQL catalog (including `0115_imported_file_mirrors_0473.sql`) is required.
The CLI checks checksums for *all* applied migrations, validates all staging
row digests and table receipts, checks row counts and relationships and writes
its live import receipt in the same transaction. PostgreSQL migration scripts
already applied to other installations must not be rewritten.

Stop Core writers and prevent PostgreSQL Backend / setup wizard from accepting
requests during transfer. Make and retain an independent off-host SQLite backup.
Do **not** import into an already running/used PostgreSQL deployment.

## Commands

```bash
# On a disposable EMPTY PostgreSQL database, after applying the full schema:
export LAUNCHER_POSTGRES_DSN='postgres://...'
launcher-sqlite sqlite-to-postgres-live \
  --backup /private/backups/core-327.db --ack-live-import --timeout 30m

# If staging was committed but the live phase failed, fix the cause and retry
# without overwriting staging. This does NOT re-run the physical transfer.
launcher-sqlite sqlite-to-postgres-live \
  --from-staging --ack-live-import --timeout 30m
```

The previous `sqlite-to-postgres --ack-staging-only` remains supported and
**does not write live tables**. `sqlite-to-postgres-live --from-staging` also
accepts staging created with that earlier command, provided its receipt/schema
is current and the target is still pristine.

The live receipt is stored in `public.sqlite_live_receipts_0473`. A successful
result contains `verified=true`, source SHA-256, per-table row counts, and
`readyForBackendCutover=false`. The last flag is intentionally false: 0.47.3
only moves representable Core project/profile/release, channel, user/role, audit
and manifest file metadata. It does not transfer file bytes or separately
managed HTTP/Coordinator/Redis/S3 state.

## Field mapping

| SQLite Core source | SQLRepository target |
| --- | --- |
| `projects` | `projects` |
| `profiles` | `profiles` (revision/digest and Minecraft launch settings retained) |
| `profile_revisions` | `profile_revisions_0221` (JSON spec retained) |
| `channels` | `release_channels` |
| `releases` | `release_versions` (signed manifest JSON retained) |
| `channel_heads` | `channel_heads` (exact head ID/revision/digest) |
| `roles` | `roles` (exact source role permissions, seeded target replaced) |
| `users` | `users` and canonical `auth_identities` (password hashes, local login identity and dates kept, epoch=1 only) |
| `project_user_roles` | `project_user_roles`, plus `users.project_roles` projection |
| `audit_events` | `audit_events` (including correlation/reason/job) |
| `releases.manifest.files[]` | `files` (derived stable ID, all file metadata incl. mirrors) |

SQLite INTEGER nanosecond times become PostgreSQL `TIMESTAMPTZ`; optional zero
values become NULL. SQLite 0/1 flags become booleans. JSON is validated and
stored as PostgreSQL JSONB. The source's signed manifest fields are not re-signed
or intentionally edited. Derived file IDs are SHA-256 of release ID and path;
Core did not have separate file IDs.

## Fail-closed cases

- Unrecognized/future Core schema, invalid/incomplete `dbmigrate` state,
  mutated staging data, extra/missing/unmappable source columns or rows;
- Missing FK prerequisites, malformed JSON or unsigned published manifest;
- Any nonempty source state in tables not explicitly mapped in 0.47.3,
  including sessions, MFA, revoked tokens, active leases, jobs, bridge nodes,
  extension packages, and their durable security/audit state;
- Existing PostgreSQL user/project/application rows, altered setup defaults,
  or a prior live import; source user `auth_epoch != 1`;
- Broken file metadata or database constraints.

A failed live phase **rolls back live table writes** while leaving immutable
staging and original verified backup unchanged. If the connection drops during
COMMIT, **check `sqlite_live_receipts_0473` and live data before retrying**;
never assume an unknown commit result was rolled back.

## Independent acceptance

Run `go test ./internal/sqlitepg ./internal/repository ./cmd/launcher-sqlite`
with Go 1.27.3 and a dedicated empty `LAUNCHER_PG_LIVE_TEST_DSN`. The PostgreSQL
integration test applies real migration SQL, makes a Core backup, imports it,
reads records via actual SQLRepository and verifies refusal to overwrite a
populated database. A full project cutover still requires subsequent 0.47.4
state/storage parity and 0.47.5 freeze/cutover plus real Minecraft launch checks.

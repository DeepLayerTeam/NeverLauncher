# NeverLauncher 0.32.2 — SQLite Core Repository (DEP01 core)

## What is executable

`services/api/internal/sqlitecore` is **real SQLite/WAL persistence**, using the
DEP00 exclusive-owner/verified-filesystem store and immediate serialized writes.
The core APIs accept a `context.Context` and return errors for missing records,
constraints, corruption and unknown transaction commit outcomes. There is no
memory delegation. Implemented operations:

- Projects: create/update, list, get.
- Profiles: create, revision-CAS update, list, get, immutable revision history,
  integrity-checked immutable profile snapshots.
- Channels and releases: channel upsert/list, draft creation from a pinned
  profile snapshot, draft manifest update, trusted-Ed25519 publication with
  atomic channel-head CAS and audit, published lookup verifying signer + stored
  digest, immutable published release restrictions.
- Users: create/update, get by ID/case-insensitive email, list, normalized
  per-project role assignments, explicit password change and account disable,
  monotonic `auth_epoch` for later session revocation, last-active-owner guard.
- Roles: eight built-in permission sets persisted in SQLite, referenced by
  foreign keys. Role editing is **not** enabled.
- Audit: append-only durable events, immutable triggers, atomic write together
  with core mutations; listing with a bounded limit.

## Local maintenance commands

Requires Go 1.27.3+, a real local **ext4, XFS or Btrfs** filesystem on Linux,
user-owned directory mode `0700`, local DB mode `0600`. Shared/NFS/overlay
volumes are refused. No SQLite-in-memory, no second writer process.

```sh
umask 077
mkdir -p /var/lib/neverlauncher/sqlite
chmod 0700 /var/lib/neverlauncher/sqlite
neverlauncher-sqlite verify --db /var/lib/neverlauncher/sqlite/core.db
neverlauncher-sqlite core-init --db /var/lib/neverlauncher/sqlite/core.db
neverlauncher-sqlite core-status --db /var/lib/neverlauncher/sqlite/core.db
```

`core-init` creates/migrates the core schema inside one durable SQLite
transaction and revalidates the persisted state. `core-status` requires a
previously initialized file and does not seed/migrate it. The status returns
counts for durable core tables. The package is also exercised by a **local,
privileged maintenance CLI**, not by an unauthenticated HTTP API:

```sh
umask 077
printf '%s\n' '{"id":"my-project","name":"My Project"}' > /var/lib/neverlauncher/sqlite/project.json
chmod 0600 /var/lib/neverlauncher/sqlite/project.json
neverlauncher-sqlite core-put --db /var/lib/neverlauncher/sqlite/core.db \
  --kind project --input /var/lib/neverlauncher/sqlite/project.json --actor operator
neverlauncher-sqlite core-get --db /var/lib/neverlauncher/sqlite/core.db \
  --kind project --project my-project
```

`core-put` supports `project`, `profile`, `channel`, `user`, and `audit`;
`core-draft` creates a draft from an immutable profile revision,
`core-update-manifest` accepts a private JSON file, `core-publish` requires a
trusted Ed25519 public key and exact `--expected-revision` (channel-head CAS),
and `core-get` reads projects/profiles/revisions/channels/releases/users/roles/
audit/counts. Every mutation requires `--actor` and writes audit in the same
SQLite transaction. All JSON inputs must be regular private files (mode 0600).
For `core-put --kind user`, specify `roleId` and `status` explicitly; a
`passwordHash` can only be supplied in the private JSON file and is never
returned by `core-get`. Local CLI access is equivalent to privileged SQLite
file ownership; do not grant it to untrusted users.

## Compatibility and security boundaries

- This is DEP01 **core only** (projects/profiles/releases/users/roles/audit).
  Authentication sessions, refresh-token revocation, federated identities,
  replay nonces, join tickets, jobs, bridge commands, extension state, packages,
  coordinated leases, general file/blob storage and admin access are **NOT**
  implemented on SQLite in this version. `NEVERLAUNCHER_REPOSITORY_DRIVER=sqlite`
  remains forbidden (fail-closed) in the main Backend. No single-node production
  deployment or parity with PostgreSQL is claimed yet.
- A caller must supply a nonempty actor for every core mutation. Publication
  also requires an explicit list of trusted Ed25519 public keys, matching the
  signed canonical JSON payload. Self-declared unsigned or untrusted keys are
  rejected. Game trust generation/rollback extensions are not implemented here
  and deliberately fail closed. Application-level authorization and full
  signing/preflight policies must be enforced when future API wiring is added.
- No implicit migration or synchronization between PostgreSQL and SQLite is
  implemented (DEP07). Using `core-init` on a separate file does **not** copy
  existing project data. Before upgrading, create a verified backup of the
  current database via the supported mechanism for its engine.
- An error wrapping `sqlitedurable.ErrCommitUnknown` means the write's durable
  outcome is uncertain; reconcile by immutable ID before retrying.

## Acceptance tests

On an ext4/XFS/Btrfs runner with the exact pinned Go and SQLite versions:

```sh
cd services/api
go mod download
go mod verify
NEVERLAUNCHER_SQLITE_TEST_ROOT=/secure/ext4/sqlite-tests \
  go test -race -count=1 -v ./internal/sqlitecore ./internal/sqlitedurable
```

Tests cover actual WAL close/reopen, immutable history, stale CAS rejection,
concurrent profile writers, active owner protection, role-epoch increments,
rollback after constraint failure, append-only audit, trusted signer enforcement,
channel-head atomics and published release immutability.

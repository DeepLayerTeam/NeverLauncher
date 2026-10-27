# Migration Center 0.33.1 — Durable Workflow

0.33.1 provides a **working transactional execution service** on the production PostgreSQL backend. It records target readiness and Never project inventory in a replayable, append-only event log. It intentionally **does not implement Gravit source parsing, account import, cutover or rollback**. A run ending in `prepared` only means that the target baseline is checkpointed; it does not mean the migration is compatible or completed.

## Apply migration

Apply the regular API PostgreSQL schema migration `0089_migration_workflow_0331.sql` with the existing `nl db migrate` workflow before invoking these commands. The service fails closed with HTTP 503 on repositories that do not implement persistent migration storage.

## CLI

```sh
nl migrate gravit create --backend https://launcher.example --token "$TOKEN" --project example --key change-request-2026-001
nl migrate gravit list --backend https://launcher.example --token "$TOKEN" --project example
nl migrate gravit execute --backend https://launcher.example --token "$TOKEN" --run <id>
nl migrate gravit status --backend https://launcher.example --token "$TOKEN" --run <id>
nl migrate gravit events --backend https://launcher.example --token "$TOKEN" --run <id>
nl migrate gravit pause --backend https://launcher.example --token "$TOKEN" --run <id>
nl migrate gravit resume --backend https://launcher.example --token "$TOKEN" --run <id>
```

Only `settings:manage` administrators can access API routes. The backend never follows filesystem paths from requests. A stable idempotency key is required for creation retries.

## Execution and failure semantics

- A run starts with `target_check`, then records `target_inventory`; each successful step advances the revision and adds a journal event in the **same PostgreSQL transaction**.
- Claims use PostgreSQL atomic `UPDATE ... RETURNING` with a lease and monotonically increasing fencing epoch. The old worker's checkpoint fails even if its HTTP request finishes after the lease is reacquired.
- Only one request can own an active run. If a process is terminated, another execute request may resume after the lease expires. A canceled HTTP request cannot promise a checkpoint; inspect status before retrying.
- On a step error, the failure and message are persisted; an operator can resume after addressing the cause. Pause deliberately refuses to preempt a live worker; wait for its lease/checkpoint.
- The 0.33.1 steps only read Never target metadata and persist an SHA-256 inventory summary. They cannot mutate source files or launcher state. This makes checkpoints side-effect-safe.
- Event queries support a strictly increasing sequence cursor (`?after=`); per-run order is by committed sequence IDs.
- A `prepared` run stays immutable until a later version adds real source assessment handlers and explicit approval gates.

## Operational constraints

No implicit worker starts at boot. Execution is synchronous over HTTPS, and automation can retry it safely using the returned run ID. PostgreSQL is mandatory for this feature; SQLite-only application repository parity is not claimed by 0.33.1. Long-running Gravit copy/import tasks will require their own idempotent step handlers in later releases.

## Verification

`python3 scripts/version/manage.py check` must pass. The workflow `.github/workflows/migration-center-0331.yml` runs race-enabled PostgreSQL integration tests, CLI tests and a production Admin TypeScript/Vite build. A green CI run is required before claiming this feature is production-qualified. This archive was constructed without access to the repository's Go 1.27.3 toolchain or a live PostgreSQL service; those integration steps have **not** been certified locally.

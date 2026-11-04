# NeverLauncher 0.51.4 — partition safety and fencing

## What the code actually enforces

- PostgreSQL (`durable_scope_leases`, `durable_jobs`, `event_outbox`) is authoritative for durable job claims, mutation lease ownership, fencing sequence and completion. `clock_timestamp()` from the **same PostgreSQL primary** defines the expiry; node clock skew cannot move a lease deadline.
- Under `FOR UPDATE` / `FOR UPDATE SKIP LOCKED`, only one transaction can acquire a given row at a time. Every takeover advances `lease_fence` / `fencing_token`. An expired lease token cannot renew, release, fail, terminate or complete work in PostgreSQL. Expired jobs/outbox entries at their maximum attempt count are retired rather than left indefinitely running. SQL mutations of the release's channel pointer are transactionally protected by the current job token, scope token, fencing sequence and channel-head CAS.
- An outbox lease that expires before ACK cannot be marked delivered by the original worker. **Outbox delivery remains at-least-once**, not exactly-once: a side effect may have occurred before a worker failed. Consumers must deduplicate using the stable event/operation identity.
- Redis ServerBridge command lease identity is validated *before* key normalization; malformed distinct IDs cannot map to the same ephemeral Redis key. PostgreSQL's command journal remains the durable control authority. Lost ServerBridge command ACKs must stay `indeterminate`, **not** be automatically re-executed.

## Operational conditions — mandatory

1. Run the control plane against a PostgreSQL cluster that enforces a **single writable primary using quorum/fencing (STONITH or equivalent)**. Two writable PostgreSQL leaders on a split network can each accept valid leases: the application's SQL transaction fences cannot correct a broken PostgreSQL cluster. Patroni `/primary` probes and HAProxy alone do not prove fencing across partitions.
2. Use a Redis deployment with a verified primary and fail-closed leases, and ensure the routing path does not let one API node keep communicating with an old independently writable primary. If Redis is unavailable, control API must return an error rather than bypass coordination.
3. Never independently mount writable SQLite repository files, Minecraft worlds or extension files on two hosts. Minecraft process memory and world writes require a **separate host/world fencing procedure**; PostgreSQL leases alone do not make world folders safe for concurrent writers.
4. API/worker clocks should still be synchronized for log correlation, signatures and TLS. PostgreSQL's timestamp authority only fixes the **lease expiry** part of the problem.
5. Treat unknown completion after a partition as `indeterminate` and investigate the persisted operation journal. Never blindly resubmit `server.shutdown`, `server.save`, monetary/admin mutations or arbitrary console commands with a fresh idempotency key.

## Reproducible verification

- With real PostgreSQL, run `LAUNCHER_DURABLE_DSN=postgres://... go test -race -count=1 -run 'Test(PostgresPartitionFencing0514|PostgresExpiredLeaseFailClosed0514)' ./internal/repository` from `services/api` (Go version from `go.mod`). Tests use two independent SQL pools, expire one owner's lease via PostgreSQL, and assert monotonic takeover and rejection of stale operations.
- The CI job `.github/workflows/partition-fencing-0514.yml` starts PostgreSQL 17 and runs these tests as well as Redis identity regressions. Skipped/missing PostgreSQL integration tests are not release evidence.
- On the independent-host HA testbed, partition API/worker node A from PostgreSQL and Redis while keeping node B connected. Verify A cannot commit new metadata, acknowledge delivered events or claim Bridge leases; B continues using the primary. Restore A's network and ensure its old tokens are rejected and new operations are assigned fresh fencing generations. Record DB instance timeline, cluster quorum state, affected operation IDs, before/after rows, and exact runtime digests.
- Separately partition the PostgreSQL or Redis **cluster itself** and force a leader failover, confirming old primary writability is fenced. Use an isolated, disposable lab with authorization; do **not** run ad-hoc firewall rules against production hosts. Record RTO/RPO, rejected transactions, and any indeterminate externally applied side effects.

## Deliberate limitations

This patch fixes real application-side time-of-check fencing and Redis identity collisions. It does not implement PostgreSQL leader election, Redis quorum/fencing, remote network partition injection or live host/world ownership takeover. **0.51.4 HA GA must remain BLOCKED** until physically separated nodes, real partition scenarios and all external dependencies have been independently certified. No unit/integration test or configuration declaration can substitute for those tests.

# Launcher 0.32.16 — Production RC (test gate, not GA certification)

This release adds an executable, fail-closed test gate and fixes a real
capacity-measurement defect. It does **not** make the SQLite-only HTTP backend
available, implement SQLite → PostgreSQL cutover, or prove multi-host HA.

## What runs

`python3 scripts/rc/production_rc.py --output "$RUNNER_TEMP/launcher-03216-rc.json"`

The gate calls **real** `go test -json -race -count=1` under Go 1.27+ on the
pinned project dependencies. It enforces named tests for: SQLite auth, MFA,
revocation, Minecraft UUID/session, join tickets, replay nonces, durable jobs,
leases/fencing, outbox, ServerBridge, package verification, SQLite crash and
owner locks, online backup/restore, SQLite coordinator, the PostgreSQL staging
migration, live PostgreSQL advisory locks, live Redis coordinator, live S3
cross-client write/read/hash/delete, existing HTTP authentication and the
capacity benchmark's failure handling. All expected tests must report PASS.
SKIP, missing test, package failure and timeout **block** release; a green
`go test` without executed assertions is insufficient.

The Redis/PG and live S3 tests use **isolated ephemeral CI systems**, never
production. S3 probe objects use temporary names and must be cleaned up.
The concurrency exercise is a bounded correctness stress case; the observed
throughput belongs only to that runner and is not a production SLO.

## Required environment

Use an isolated ext4/XFS/Btrfs directory with mode `0700`, Go 1.27.3, an
isolated PostgreSQL database, Redis and an S3-compatible test bucket.

- `LAUNCHER_SQLITE_TEST_ROOT` and `LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS=1`
- `LAUNCHER_PG_TEST_DSN`, `LAUNCHER_GROWTH_TEST_PG_DSN`
- `LAUNCHER_GROWTH_TEST_REDIS_URL`
- `LAUNCHER_RC_S3_ENDPOINT`, `_BUCKET`, `_REGION`, `_ACCESS_KEY`, `_SECRET_KEY`

These are secrets/isolated fixtures supplied by the CI environment, not
bundled with a release. Missing configuration blocks the gate. The gate
creates a restricted JSON evidence file **only after all suites pass**; the
file is a test execution receipt, not a signature or an authorization to GA.

To run the self-tests of the receipt verifier (these are not product tests):

```bash
python3 -m unittest discover -s scripts/rc -p 'test_*.py' -v
```

## Required before labeling 0.32.16 production-certified

1. Successful exact-commit live RC workflow plus existing platform signing,
   native launcher, Guard, ServerBridge and independent GA gates.
2. Real end-to-end smoke with an installed production configuration, a player
   login, Minecraft server join and access revocation. The checked HTTP tests
   are real HTTP handler tests but **not** that complete deployment scenario.
3. Separate controlled multi-host Network/HA failover, partition, stale
   worker/fencing and restore exercises under representative load.
4. Validation of an actual release artifact's BOM, signatures and rollback.

Never derive capacity limits from the bounded synthetic rate-limiter stress
or benchmark fixture. Never use this gate to override the existing unsupported
SQLite-only HTTP deployment prohibition.

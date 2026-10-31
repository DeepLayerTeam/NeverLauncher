# Launcher 0.32.15 — DEP10 Capacity & Diagnostics

This release includes **real process and infrastructure measurements**, a 60-second rolling request window, a read-only bounded benchmark utility, and operator recommendations. It **does not** claim to know the maximum throughput of your infrastructure without measurements on it.

## Operational interfaces

- `launcher-api diagnose capacity` — JSON with observed disk usage, PostgreSQL connections/DB size/job and outbox backlog, Go heap, goroutines, and recommendations. Exit `2` for failed probes or critical conditions. Run with the SAME environment as the service; secrets stay on the host.
- `GET /api/v1/operations/capacity` — last sampled JSON, requires existing `diagnostics:read`; returns HTTP 503 if no verified/fresh sample.
- `GET /metrics` — Prometheus gauges. Samples are collected in the background at 30-second intervals and never query PostgreSQL on the HTTP request path. Keep this pre-existing endpoint isolated to your monitoring network or reverse proxy.
- HTTP middleware — last-minute request count, 429 count, 5xx count, current in-flight, average and histogram-estimated p95. No route labels, tokens, IPs, or player identifiers.
- `launcher-capacity-bench --confirm --url http://127.0.0.1:8080/api/v1/status --max-workers 16 --step 8s` — explicitly requested GET load test with 1,2,4,8,16 concurrent requests, automatically stopping on first failing step. `--allow-remote` is also required for non-loopback targets, which you must own/control. Responses contain observed RPS, p95/p99, failures and rate limiting. Do not run against third-party endpoints.

## Measured conditions and actions

| Measurement | Alert condition | Operational action |
|---|---|---|
| Free local filesystem space | Below 2 GiB **or** below 10% | Move storage/backups to a larger volume, test restore; do not fill the WAL volume |
| PostgreSQL client connections | ≥80% of `max_connections` | Profile leaking sessions, bound pools, use PgBouncer before increasing replicas |
| Pending durable jobs | ≥500 | Investigate workers, retries and DB latency; scale workers only with lease/fencing testing |
| Oldest pending job age | >60 seconds | Check worker progress, retry delays and dependencies |
| Running job leases expired | >0 | Investigate stale workers and idempotent recovery; never blindly replay unsafe actions |
| Outbox backlog | ≥500 | Check dispatcher, downstream acknowledgements and idempotency |
| HTTP 5xx percentage | ≥5% of ≥20 requests / 60s | Diagnose failures before increasing replicas |
| HTTP 429 percentage | ≥10% of ≥20 requests / 60s | Investigate abusive load and legitimate client retry patterns |
| HTTP p95 | >1s of ≥20 requests / 60s | Profile handlers and dependency pressure |

**These are operator-defined warning thresholds, not published benchmarked maximum limits.** No auto-scaling or automatic topology transitions occur. A return code of zero does not certify HA/failover. More than one Backend in Network/HA must pass independent lease/fencing, failover, network-partition, storage and authentication tests. SQLite-only HTTP Backend is still blocked in the existing deployment gate.

## Coverage and caveats

- The API's current production HTTP repository is PostgreSQL; these measurements cannot certify unsupported SQLite-only HTTP production.
- Filesystem sampling uses `statfs` on existing local paths. A missing volume is an explicit probe error, not zero usage. The report includes no storage paths.
- PostgreSQL samples are read using separate bounded SQL connections, a five-second query deadline, server-wide connection counts, and queue/outbox SQL aggregates. Failed queries mark the report unverified and are not treated as empty queues.
- S3 storage quota is not exposed by a standard portable S3 API; therefore no numeric quota is invented. Redis lease and S3 round-trip availability remain subject to existing `/ready` and `diagnose growth` validation.
- A benchmark of `/api/v1/status` or `/ready` establishes the throughput **only of that selected endpoint**, in that test environment and time window. Auth flows, release publishing, large downloads and actual players need their own representative workload experiments.
- Sampling never writes to SQLite or PostgreSQL and does not mutate jobs, leases, nonces, identities or authorization state.

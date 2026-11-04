# NeverLauncher 0.51.10 — хаос-тестирование нескольких узлов и наблюдаемость

This document describes **executable fault injection** against two or more *independent Docker hosts* with NeverLauncher multi-host deployment. It is **not** a production GA certificate. Commands here intentionally disrupt live containers; run only on an authorized disposable/test deployment with separate, independently managed PostgreSQL/Redis/S3 and externally load-balanced HTTPS ingress.

## Предварительные условия (запрет при ошибке)

1. Deploy `deploy/production/docker-compose.multi-host.yml` on at least two different Docker hosts; run the multi-host 0.51.2/0.51.7 health/inventory checks beforehand. Never run the chaos CLI with the single-host Network-HA Compose file. The tool validates immutable images, distinct machine IDs, API+worker readiness and shared external PG/Redis/S3 round trips via `multi_host_0512.py` before fault injection.
2. Install **both** `scripts/operations/multi_host_chaos_05110.py` and `scripts/operations/multi_host_0512.py` with the same files/paths on the operator workstation and each Docker host. Allow the SSH operator only the required Docker operations. Strict known_hosts verification, noninteractive SSH and an explicit `I-ACCEPT-REAL-OUTAGE` token are mandatory. Use separate SSH principals for each host. Do not run unrelated application releases or database migrations concurrently with drills.
3. Put `--state` and `--report` into a pre-created operator-owned private directory (`0700`), e.g. `/var/lib/neverlauncher-chaos`; do not reuse filenames. Keep private recovery journals until a complete verified repair. A failure or SIGKILL can leave a remote node isolated. **Run `recover` before new drills**.
4. On each node that may be network-partitioned, create a *private, regular `0600`* `/opt/launcher/deploy/production/.chaos-approval-05110.json`, scoped to the real node ID and current project:

```json
{"project":"launcher", "nodeId":"lab-a", "allow":["network-partition"], "expiresUtc":"2026-11-03T21:00:00Z"}
```

The expiration must be in the future and within four hours. Replace this illustrative timestamp with a valid UTC expiry. `host-stop` instead needs the operator's explicit disruption token. Never commit approval files or credentials.

## Реальное внедрение сбоев и восстановление

Run from a trusted operator host (absolute remote paths are mandatory):

```bash
python3 scripts/operations/multi_host_chaos_05110.py run \
  --project launcher --directory /opt/launcher/deploy/production \
  --node a=ops@node-a.example.org --node b=ops@node-b.example.org \
  --failed-node a --fault network-partition \
  --edge-url https://launcher.example.org/ready \
  --state /var/lib/neverlauncher-chaos/partition.state.json \
  --report /var/lib/neverlauncher-chaos/partition.report.json \
  --allow-disruption I-ACCEPT-REAL-OUTAGE
```

For a **repeatable four-case-per-iteration E2E suite**, pre-create an **empty private** directory (`mkdir -m 700 /var/lib/neverlauncher-chaos/suite-01`). Then run:

```bash
python3 scripts/operations/multi_host_chaos_05110.py suite \
  --project launcher --directory /opt/launcher/deploy/production \
  --node a=ops@node-a.example.org --node b=ops@node-b.example.org \
  --edge-url https://launcher.example.org/ready \
  --suite-directory /var/lib/neverlauncher-chaos/suite-01 \
  --iterations 1 --allow-disruption I-ACCEPT-REAL-OUTAGE
```

This runs a full host-service stop and a Docker network partition on **each** host, in deterministic order. A failed or unrecovered case aborts the remaining sequence and writes `suite-report.json` plus separate per-case evidence and SHA-256 hashes. Maximum repetitions: three. Recover the specific `*.state.json` journal with `recover` before another run. This does not certify external storage quorum safety, real JVM continuity or guaranteed notification delivery.

Choose `--fault host-stop` for a complete shutdown of the four product services (`api`, `worker`, `admin`, `ingress`) on one Docker host. Repeat for a second node and varied production-like loads; each run needs distinct state/report paths. The network partition uses *real* `docker network disconnect --force` on the API and worker containers and separately checks that both were removed from the `launcher_launcher` bridge. This is a **Docker-container partition**, not a physical host power cut, inter-switch network blackhole or quorum failure.

The controller requires three consecutive HTTPS readiness successes after disruption, five sustained additional probes, and healthy remaining API/worker nodes with live dependency round trips; it records sample success/failure and p50/p95 latency as observed, not inferred. It always attempts node restoration, then rechecks the entire cluster. A successful isolated API readiness response is not enough to claim no user-visible errors during the outage.

If SSH or the operator process dies during injection, execute:

```bash
python3 scripts/operations/multi_host_chaos_05110.py recover \
  --project launcher --directory /opt/launcher/deploy/production \
  --node a=ops@node-a.example.org --node b=ops@node-b.example.org \
  --edge-url https://launcher.example.org/ready \
  --state /var/lib/neverlauncher-chaos/partition.state.json
```

This reconnects the original verified container IDs **with the original Compose DNS aliases** (required for ingress to resolve `api`) or restarts a stopped host and verifies the baseline. If the original container was replaced, the tool **refuses** to reconnect an unverified replacement: repair manually and keep the journal as evidence. Recovery is never a database/world rollback and cannot silently undo confirmed writes.

## Оповещения и воспроизводимые наблюдения

`deploy/production/docker-compose.observability.yml` now supports distinct Prometheus alerts via `LAUNCHER_PROMETHEUS_ALERT_RULES`. Generate operator-owned Prometheus scrape/alert configs for **different direct host ingress names**, not two DNS names backed by the same LB:

```bash
mkdir -m 700 -p /opt/launcher/deploy/production/monitoring/ha-05110
python3 scripts/operations/multi_host_chaos_05110.py monitor-config \
  --node-url a=https://node-a.example.org/ready \
  --node-url b=https://node-b.example.org/ready \
  --edge-url https://launcher.example.org/ready \
  --output-directory /opt/launcher/deploy/production/monitoring/ha-05110
```

The generated files are JSON documents with `.yml` extension (strictly valid YAML); use them directly with Prometheus. Set `LAUNCHER_PROMETHEUS_CONFIG=./monitoring/ha-05110/prometheus-05110.yml` and `LAUNCHER_PROMETHEUS_ALERT_RULES=./monitoring/ha-05110/alerts-05110.yml` **in the Compose operator environment**. Keep the existing Blackbox exporter from the observability Compose overlay. The strict `https_2xx_strict` module validates TLS, only accepts status 200, and refuses redirects. Configure an Alertmanager HTTPS webhook receiver using the existing `observability_0459.py configure` in a private file. Confirm Alertmanager actually sends a test notification to the operator's receiver; an HTTP 200 from Alertmanager's API is **not** receipt proof.

Three real alert rules are generated: per-host ingress down; fewer than two healthy host ingresses; public HTTPS ingress down. They fire after a real 30-second fault; the default Alertmanager check waits up to 100 seconds. To require observation of an active Alertmanager alert in the fault test, append `--alertmanager-url https://alerts.example.org --alert-name NeverLauncherHostIngressDown`. Without these arguments report field `alertState=UNVERIFIED` does not claim notification delivery. A monitored drill cannot report PASS if the expected alert was not observed.

## Подтверждения и независимый допуск

Each result is written to a new `0600` JSON file only after recovery has been attempted. Result fields distinguish actual fault, survivor checks, edge samples, Alertmanager observation, duration, recovered state and unverified conditions. Never record credentials, bearer headers, full environment or raw Docker logs. The `recover` journal survives a failed restore, with a strict manual fix path.

Actual acceptance still requires **physical** host power loss, real network partition of both infrastructure and database-quorum links, Patroni/Redis failover, S3 replication/recovery, stale-lease/fencing scenarios, durable worker/outbox readback, Minecraft JVM world snapshot/rejoin, downstream alert notification, and quantitative RTO/RPO/SLO measurements across independently deployed final release binaries. Existing 0.51.3 dependency drills and 0.51.8/0.51.9 recovery can be run independently and their evidence linked by the operator; this 0.51.10 script does not falsely aggregate their results into a complete GA certificate. There are no automatic sanctions or forced database primaries.

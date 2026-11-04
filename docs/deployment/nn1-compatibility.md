# 0.51.6 — совместимость N/N−1: API, обработчик, ServerBridge, PostgreSQL

This release supports the **specific 0.51.5 ↔ 0.51.6 control-plane binary pair** on the same PostgreSQL database. It does **not** claim that arbitrary older or future versions are compatible.

## исполняемое поведение и ограничения

- API and worker remain separate `network-ha` processes. The existing PostgreSQL durable jobs, outbox ownership, idempotency and ServerBridge fencing remain authoritative; no new writer or transport is introduced in 0.51.6.
- Both binaries use the **same 117 immutable PostgreSQL migrations as 0.51.5**, with identical file names and SHA-256. Thus 0.51.5's strict migration checker does not encounter an unknown migration after deploying 0.51.6. **Do not run migrations or expand/contract DDL during the mixed period.** For later versions, add a separately verified compatibility route; never reinterpret unknown migrations as compatible by default.
- `dbmigrate.StatusOf` in the new binary is read-only. The separate migration role still holds the existing PostgreSQL advisory lock and applies migrations transactionally. A missing tracking table, unsealed checksum, changed checksum, unknown migration or pending migration still rejects startup/readiness.
- Existing HTTP API v1, ServerBridge v3 (and negotiated v2) and durable PostgreSQL jobs/outbox protocol are unchanged. The compatibility admission performs **real** `/ready` probes against API and worker on each host, followed by `/api/v1/status`, `/api/v1/loaders`, `/api/v1/runtime/requirements`, and signed ServerBridge capability-negotiation endpoint. It compares stable wire response fingerprints between the running versions, including trust signing key fingerprint and Bridge feature digest.
- The production multi-host launcher still **rejects arbitrary mixed images**. During a 0.51.5→0.51.6 rolling deployment the dedicated verifier is the only supported multi-version admission. Never use `--skip-growth` or relax image immutability to turn a FAIL into PASS. Actual rollout/drain orchestration belongs to 0.51.7.

## подготовка

1. On **each host**, deploy the updated `ha_inventory_0511.py`, `multi_host_0512.py` tools and this version's source tree before changing the running containers. Old running binaries are supported: the script probes them through real HTTP readiness and public routes, not through `VERSION`, image tags or `go build` output.
2. Ensure each Docker host uses its own pinned OCI backend digest shared by the *local* API and worker. During the window the two hosts may have different digests, **only** when the running versions are exactly `0.51.5` and `0.51.6`. Other images remain pinned, and each host must continue to reference the same PostgreSQL, Redis, S3 and public origin.
3. Run from a trusted operator host with SSH host keys already pinned and `psql` installed. Put a **single** primary PostgreSQL URI (`postgresql://user:password@db.example/launcher?sslmode=verify-full`) into a private `0600` file. Do **not** pass the DSN on the command line or add it to reports; use an appropriate TLS root CA and host certificate.
4. Ensure that all 117 expected migration rows with their sealed checksums are present in `schema_migrations` and that the DSN points to the primary (not an async read replica). The verifier reads actual PostgreSQL data inside a read-only transaction; it does not write data or change the schema.

## Run

```sh
python3 scripts/operations/nn1_compat_0516.py \
  --node a=ops@node-a.example --node b=ops@node-b.example \
  --directory /opt/launcher/deploy/production --project launcher \
  --edge-url https://launcher.example \
  --pg-dsn-file /run/secrets/launcher-primary-dsn \
  --require-mixed --output /run/launcher/nn1-mixed-0516.json
```

Before and after the mixed period, omit `--require-mixed` to accept a uniform cluster of either supported version. The report file must not exist; create a private report directory and retain the result with the actual image digests and independent incident evidence. A nonzero exit code or an absent report blocks traffic promotion. The verifier rejects clocked-out or unsupported worker versions, mismatched real HTTP contracts, unhealthy dependencies, unexpected migrations, changed signing key fingerprint and mismatched host identity.

## границы приёмки

The executable checks establish **live admission criteria**, not a completed rolling deployment or zero-downtime guarantee. Independently verify real idempotent command delivery/ACK across old/new workers and actual Minecraft + ServerBridge under load; validate PostgreSQL HA writer fencing and external LB during a physical failure. No native three-OS/gameplay or two-host fault-injection evidence is included in this source archive. No incompatible DB DDL, world snapshot migration, extension state upgrade or JVM agent hot swap is claimed as rolling-compatible.

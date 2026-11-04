# NeverLauncher 0.51.9 — cross-host disaster recovery

**Status: implementation + local regressions, not independently qualified HA/DR.**

The executable `scripts/operations/cross_host_recovery_0519.py` recovers a **verified, frozen 0.51.8 checkpoint** onto different physical hosts. The restore process is intentionally split into `prepare`, `replay-postgres`, and `admit`: a failed prepare cannot silently activate a partially restored control plane. It never overwrites a live PostgreSQL directory, populated S3 bucket, pre-existing Docker volume, Minecraft world directory or another project. A private fsync-backed `recovery-state-0519.json` tracks completed steps; an interrupted restore is **not automatically retried** over partially written data. Reconcile or discard the isolated recovery installation, then use a new destination.

## Prerequisites (actual infrastructure, not placeholders)

- A complete `consistent_backup_0518.py backup` checkpoint, validated with `consistent_backup_0518.py verify`, and its pgBackRest repository including every required WAL segment. Both must be available on the new, isolated PostgreSQL recovery host. Encrypted offsite retention and the separately escrowed trust roots, authentication signing keys, JWT/ServerBridge keys, TLS certificates and third-party provider credentials must remain recoverable. The `trust-hashes.json` file is **fingerprints, not key material**.
- At least two **new physical Docker hosts**, each running the unchanged pinned 0.51.9 binary image, the `docker-compose.multi-host.yml` deployment and installed `cross_host_recovery_0519.py` and `multi_host_0512.py`. These Docker hosts must not be any of the physical hosts recorded in the checkpoint. Docker Compose configuration, external PostgreSQL DNS, Redis primary/cluster, empty new versioned S3 bucket, TLS key/cert and load balancer routes must be provisioned in the approved infrastructure. **Do not launch containers or `volume-init` before restore**.
- A new PostgreSQL host/user with a private empty PGDATA parent, an operational pgBackRest stanza and WAL storage, and `pg_ctl`, `psql`, `pgbackrest`. Run `prepare` and `replay-postgres` **on that new host** (the recovery journal and restored PGDATA must stay together). `pg_ctl` refuses root. Supply a dedicated empty private socket directory. PostgreSQL is started with UNIX sockets only, replayed to the cohort LSN, checked for pause, promoted and then stopped; the site's PostgreSQL/Patroni service manager subsequently owns the promoted files. No app traffic is admitted during this sequence.
- New game hosts with fresh world destination parents, stopped game supervisors and no running Minecraft JVMs in those destinations. Configure their new ServerBridge identities and routes **after** restoring files. Minecraft JVM/host start, server-join, identity UUID and world read/write validation are separate mandatory acceptance steps. Do not infer game-host recovery from a successful file-copy receipt.
- SSH known-hosts pinned on the operator; no shell interpolation or non-pinned network downloads. Install an OCI tar image referenced by `name@sha256:<digest>` on every new Docker host. The private work directory, trust file and optional audit ledger must have mode `0700`/`0600`. Allow adequate scratch/disk space for pgBackRest, S3, all Docker volumes and world archive transfers.
- **Independently enforce fencing of the original PostgreSQL writer, API/worker nodes, ServerBridge authorities and game hosts** before replay promotion or ingress cutover. The command-line `--source-fenced` acknowledgement is not a fencing mechanism; use actual power/network/storage/Patroni authority controls and independent evidence. Redis must start without stale leases or AOF from the old cluster. Do not copy Redis transient state.

## 1. Prepare fresh destinations

Create a private operator directory on the new PG host:

```sh
install -d -m 0700 /secure/dr-0519
python3 scripts/operations/cross_host_recovery_0519.py prepare \
  --backup /secure/checkpoints/cohort-A --stanza launcher \
  --trust-file /secure/trust-hashes.json --work /secure/dr-0519 \
  --pgdata /srv/recovery/pgdata \
  --node a=ops@new-api-a.example --node b=ops@new-api-b.example \
  --world-destination survival=ops@new-game.example:/srv/new-minecraft/survival \
  --project nl-dr-recovered \
  --tar-image 'alpine@sha256:<audited-digest>' \
  --s3-bucket launcher-recovered --s3-endpoint https://new-s3.example
```

The labels after `--node` and `--world-destination` **must match every label in the verified manifest**. Use the real `manifest.json` backup label, all host labels and all world names; this example is illustrative. The controller first verifies the full source checkpoint/pgBackRest repository and independent trust fingerprints, inspects new machine IDs and empty Docker projects/volumes, checks the target bucket has **no versioned objects or delete markers**, then restores physical PostgreSQL files. It uploads the current object set to the new S3 bucket and reads every object back; it does not recreate historic S3 noncurrent versions. Each Docker volume is created separately, extracted through the pinned image and independently read back by streaming tar contents, comparing every file hash. Every game-world snapshot is checked against the original Go manifest, transported to a fresh directory and validated again after restore. Existing destinations are never overwritten.

An HTTP/OIDC/external SQL auth provider's owned state is **not cloned** by this tool. An included file-backed provider export is retained in the checkpoint, but operator must restore it to the new provider via its supported recovery route. Set original trust and auth secrets in the new deployment without printing them in logs. A successful prepare receipt is `prepared-not-admitted`; it does **not** start PostgreSQL or game/API processes.

## 2. Replay real WAL and promote in isolation

Once the old writer and game/Bridge authorities have been **actually fenced** using independent infrastructure controls:

```sh
install -d -m 0700 /srv/recovery/pg-socket
python3 scripts/operations/cross_host_recovery_0519.py replay-postgres \
  --work /secure/dr-0519 --socket-dir /srv/recovery/pg-socket \
  --pg-port 55439 --source-fenced
```

The command runs `pg_ctl start` bound only to the isolated Unix socket, polls `pg_is_in_recovery()`/`pg_is_wal_replay_paused()`, verifies that the actual replay LSN reached the sealed cohort LSN, resumes replay, waits for an actual writable primary, then runs `pg_ctl stop`. If replay, WAL or promotion fails, the operation remains blocked and no API/worker may be started. After success, configure the approved PostgreSQL/Patroni cluster manager to start **this recovered PGDATA**, with new TLS identity and a new isolated data endpoint. Verify it is not directed to the original production DB.

## 3. Admit new control-plane and measure recoverability

Start a fresh Redis cluster without old AOF, restore external providers/secrets, then configure the **same** versioned API/worker image and shared recovered PostgreSQL/Redis/S3 endpoints on both recovery Docker hosts. Verify the external load balancer is directed to the recovered topology, not the original environment. Capture the independently observed incident-onset time:

```sh
python3 scripts/operations/cross_host_recovery_0519.py admit \
  --work /secure/dr-0519 --project nl-dr-recovered \
  --pg-dsn-file /secure/recovered-postgres.url \
  --ready-url https://recovered.example/ready \
  --incident-at 2026-11-03T12:00:00Z \
  --source-fenced --external-secrets-restored
```

Before admission the tool checks the recovered external PostgreSQL primary and **all embedded SQL migration checksums and critical ServerBridge/queue columns** against the sealed catalog. It starts every restored Docker host via `multi_host_0512.py local-up`, verifying actual running Docker processes and readiness, distinct machines/replicas, external dependency health and HTTPS ingress through the configured LB. A successful run writes `recovery-result-0519.json`, with actual readiness timestamp and elapsed `rtoSeconds` from the **operator-reported** incident time. On failure the recovery journal persists and the operator must investigate; source production is never silently started or rolled back.

The default RPO field is **not measured**. `recoveryPointAgeSeconds` is the incident-to-frozen-checkpoint exposure window, **not** a guarantee of acknowledged writes retained. Optionally provide a 0600 **independently produced, immutable external audit acknowledgement ledger** with event IDs and UTC commit acknowledgement times:

```json
{"schema":"neverlauncher.dr-ack-ledger/v1","entries":[
  {"id":"event-000001","ackUtc":"2026-11-03T11:59:30Z"},
  {"id":"event-000002","ackUtc":"2026-11-03T11:59:45Z"}
]}
```

Pass `--ack-ledger /secure/ack-ledger.json` to `admit`. The controller readbacks each ID from the restored `audit_events` table with parameter-quoted PostgreSQL queries and reports the observed number preserved/missing and `sampledAuditRpoSeconds`. This is **only sampled audit-event RPO**; the ledger completeness/provenance, other SQL operations, world writes and S3 objects require independent application-level readbacks and incident evidence. An audit ledger does not replace original source fencing.

## Acceptance and limitations

The 0.51.9 code implements backup verification, distinct-host admission, isolated physical/WAL recovery, new volume extraction and verified file readback, new S3 object recovery and readback, world file restore, live API/worker restart, and timing report generation. It does **not** provision Patroni, object replication, Redis Sentinel, new game JVM authorities, secrets/KMS/identity provider state or public DNS/LB cutover; these are external prerequisites controlled by the operator. It does not perform arbitrary-time PostgreSQL PITR and then claim it matches worlds/S3. No automatic rollback of live production is supported. An interrupted partial restore must remain **BLOCKED**, not reuse populated destinations.

All of the following are required before claiming 0.51.9 as production/GA: real physical multi-host execution; forced loss of the original site; independent fencing confirmation; WAL recovery to the correct LSN; restored UUID/roles/releases/extensions; Minecraft server boot/join and world content; confirmation that games are not writing to two copies of the world; live ingress after cutover; sampled zero/known errors under workload; independent S3/DB/Redis failure drills; independently reviewed RTO/RPO/audit evidence and signs of unrecoverable sessions. Unit tests/CI cannot prove these physical facts.

# NeverLauncher 0.51.2 — executable cross-host API + worker deployment

**Result:** two independent Docker Engines, one API process + one durable worker
per host, one Admin + HTTPS ingress per host. Both processes connect to the
**same externally provisioned PostgreSQL, Redis and S3**. A health-checking
**external** load balancer routes HTTPS to both host ingress ports. Taking down
one of the product stacks leaves the other stack operational *when* the external
dependencies and the load balancer remain available. This is a runnable topology
and a controlled outage exercise, **not** proof of physical host, hypervisor,
PostgreSQL, Redis, S3 or public-edge HA.

This file is a separate production deployment. **Do not overlay it on
`docker-compose.yml` or `docker-compose.network-ha.yml`**: those files launch
single-host Redis/PostgreSQL or rely on Docker-local service discovery.

## Prerequisites and non-negotiable boundaries

- At least two separately administered Linux machines/VMs with Docker Engine
  and Docker Compose v2, with **different real** `/etc/machine-id` values.
  Separate physical failure domains must be verified by the operator: unique
  machine IDs alone do not prove distinct hypervisors, racks or power feeds.
- Reachable **external** PostgreSQL (with full TLS hostname verification), Redis
  (`rediss://`, ACL/TLS), and S3 (`https://`) shared by *all four processes*.
  **Database schema and SQLite→PostgreSQL cutover must already be approved**
  under the existing repository gate. This release does not configure
  PostgreSQL/Redis/S3 clustering (0.51.3) or partition fencing (0.51.4).
- A separately hosted external L7/TCP balancer with TLS passthrough or
  re-encryption. Direct it to `node-a:443` and `node-b:443` with SNI and Host
  matching `LAUNCHER_PUBLIC_URL`. Health-check **`GET /ready` for HTTP 200**
  over verified TLS. Remove failed hosts promptly; do not retry ambiguous
  non-idempotent HTTP requests. The external LB must survive an application
  host failure. Restrict host port 443 firewall access to trusted balancer IPs.
  Source address forwarding must use the already configured trusted-proxy
  policy, not arbitrary client-supplied `X-Forwarded-For`.
- Build/publish the **real** 0.51.2 API and Admin OCI artifacts using the
  existing release pipeline and verify source/asset provenance. Pin all four
  OCI image names to exact immutable `@sha256:...` digests. Never build a
  `:latest` tag independently on each host; the launcher refuses mutable
  image references and comparing two tags as if they were identical.
- Supply **identical** `LAUNCHER_AUTH_TOKEN_SECRET`, signing/trust settings,
  provider credentials and S3 bucket on both hosts; use strong secrets and
  private `.env` files owned by the operator. `LAUNCHER_NODE_ID` and host
  ingress IP must differ. Secrets are not synchronized by SSH or this tool;
  normal secret rotation requires the existing security/operations procedure.
- Bootstrap/migrate PostgreSQL **once, before** the multi-host rollout, with
  exclusive authorized migration; both steady-state replicas have
  `LAUNCHER_DATABASE_AUTO_MIGRATE=false`. Do not start an unapproved old API
  concurrently with the new topology. Local factory/backups/cache/extension
  working files are **not** a shared filesystem. Only PostgreSQL/S3 may be
  considered authoritative for the advertised operations; local runtime
  auth/passkey/legacy snapshot consistency requires separate E2E.

## Installation on *each* Docker host

Install the identical checked-out 0.51.2 source tree at `/opt/launcher` on each
machine. From the independent machine's console:

```sh
cd /opt/launcher/deploy/production
cp multi-host-0512.example.env .env
chmod 600 .env
# Edit the real image digests, TLS paths, shared connections, secrets,
# node ID and host bind IP. Copy neither actual secrets nor SSH private keys
# into the release archive or report files.
python3 ../../scripts/operations/multi_host_0512.py local-check \
  --directory /opt/launcher/deploy/production --output /var/tmp/launcher-preflight-a.json
```

`local-check` calls the real `docker compose config --format json` and refuses
local dependencies, unpinned OCI images, absent/mis-permissioned TLS keys,
invalid replicas, unexpected services, non-TLS external URLs and missing
machine IDs. No child process is started on failure.

If database migration is required, from **one** host during the approved
maintenance window, after backup and with old writers stopped:

```sh
cd /opt/launcher/deploy/production
docker compose -p launcher -f docker-compose.multi-host.yml pull
docker compose -p launcher -f docker-compose.multi-host.yml up volume-init
docker compose -p launcher -f docker-compose.multi-host.yml run --rm --no-deps \
  -e LAUNCHER_PROCESS_ROLE=migrate \
  -e LAUNCHER_REPLICA_ID=node-a-migrate \
  -e LAUNCHER_DATABASE_AUTO_MIGRATE=true api
```

One-shot migration exits without HTTP or worker. Check its status **and**
existing backend cutover approval before enabling requests. This route is not
an automated rolling schema migration.

If preflight succeeds and external dependencies are live, start each node:

```sh
python3 /opt/launcher/scripts/operations/multi_host_0512.py local-up \
  --directory /opt/launcher/deploy/production --output /var/tmp/launcher-node-a-up.json
```

`local-up` pulls pinned immutable OCI images, starts all local roles and waits
for actual Docker healthchecks. It executes real `/ready` from the API and
worker and real PostgreSQL/Redis-lease/S3 round-trip via existing
`launcher-api diagnose growth` before writing a private JSON report. Missing
external resources fail closed. The worker's listener binds **only** to
container loopback; API and worker have **no host-published port**. Per-process
writable volumes and image digest are checked. Container images must include
working `launcher-api`, `wget` and the official Admin package.

## Coordinate a cluster from a third, trusted machine

Use dedicated SSH operator credentials with exact pinned host keys in
`known_hosts`, `BatchMode=yes`, and the installed code and pre-provisioned `.env`
on each target. SSH account needs Docker access; this is root-equivalent
access and must be restricted. Do not run this as an anonymous web API.

```sh
TOOL=/opt/launcher/scripts/operations/multi_host_0512.py
NODES='--node a=operator@node-a.internal --node b=operator@node-b.internal'
python3 "$TOOL" cluster-check $NODES --output /var/tmp/ha-check-0512.json
python3 "$TOOL" cluster-up $NODES --edge-url https://launcher.example \
  --output /var/tmp/ha-start-0512.json
python3 "$TOOL" cluster-verify $NODES --edge-url https://launcher.example \
  --output /var/tmp/ha-live-0512.json
```

Cluster preflight checks different OS machine IDs/replica prefixes, exactly
matching image digest refs, equal public origin and shared dependency endpoint
hosts. Actual cross-node secret equivalence, provider failover, live session
round-trips and independent hypervisor placement are not inferred from these
non-secret observations; test them separately before admitting real users.

The operator should test an authenticated **read→write→read on the other
API**, a completed durable job and ServerBridge reconnection against the
real service. Check actual UUID, idempotency key, database revisions and S3
hashes. Current `/ready` and S3/Redis growth probes alone are *insufficient*
for claiming cross-replica session or game-state coherence.

## Controlled node-stack outage test (disruptive)

On a maintained staging cluster, with an independent LB and data backups:

```sh
python3 "$TOOL" cluster-drill $NODES --edge-url https://launcher.example \
  --failed-node a --allow-disruption --output /var/tmp/ha-drill-a-0512.json
```

Before the drill both hosts and the public HTTPS `/ready` must pass. The tool
stops **all four** product roles (API, worker, Admin, ingress) on node A,
checks three consecutive public HTTPS readiness probes, verifies a live API
and worker on node B, and restarts node A even after a probe failure. It
verifies both hosts and the public edge again. An error is not rewritten as
PASS, and interrupted restoration is recorded. Repeat for node B, on a
second new report path. **This simulates loss of one product stack; it is
not equivalent to pulling the power cord, dropping routes, or a hypervisor
failure.** A physical-host fault test is still required for HA GA.

Private reports use atomic exclusive write and mode `0600`; reports contain
non-secret image digest references and endpoint hostnames, not credentials or
Docker environment blocks. Store reports access-controlled. CLI status:
`0`=requested operation/check succeeded, `2`=not executed/error, `3`=runtime
was observed but a required condition failed.

## Known limitations (not silently certified)

1. PostgreSQL/Redis/S3 failover and their RPO/RTO are not handled by this release
   (0.51.3); a shared single dependency can still take down both product nodes.
2. Network partitions, stale workers/ServerBridge fencing and exact-once
   external effects require 0.51.4/0.51.5 adversarial verification.
3. Cross-replica local legacy security/session snapshot and file-based plugin
   mutation remain unverified; avoid routes relying on unsynchronized in-memory
   or local state until there is a dedicated transactional consistency test.
4. Rolling schema/application upgrades (0.51.6/0.51.7) are not implemented
   here. `cluster-up` requires all hosts pinned to **identical** images.
5. The external load balancer and DNS remain managed outside this Compose.
   An LB deployed on node A alone would recreate a host SPOF.
6. The existing final-byte, game/Guard and independent GA gates still apply.
   Lack of access to two real hosts prevents any claim of measured HA RTO/RPO.

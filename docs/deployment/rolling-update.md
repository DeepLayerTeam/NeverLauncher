# NeverLauncher 0.51.7 — executable multi-host rolling update

Scope: **control-plane API + worker only**, from **0.51.6 to 0.51.7**. No schema migration, database rewind, Minecraft process migration, unsigned component substitution or mass host restart. The external load balancer, PostgreSQL primary, Redis and S3 must already be working and independently monitored. Host-local extension files and world state are **not made highly available** by this procedure.

## Preconditions

1. At least **two distinct physical Docker hosts** run `deploy/production/docker-compose.multi-host.yml`; each has independently healthy API/worker/Admin/ingress. The public TLS LB routes `/ready` to a healthy surviving host, and keeps another route available while one host API is restarted. Use distinct node/replica IDs and independent Docker Engine identities.
2. Release engineers independently verify the **0.51.7 API OCI image digest**, signed supply-chain evidence and package/commit identity. Its `/ready` and `/api/v1/status` must reflect `0.51.7` after startup. All other images (Admin, ingress, init) stay unchanged. Release certificates and production secrets are managed separately; this controller does not sign images or bypass trust gates.
3. On **each** host install the 0.51.7 versions of `scripts/operations/rolling_update_0517.py`, `multi_host_0512.py`, `nn1_compat_0516.py`, `ha_inventory_0511.py`. The trusted operator also installs them with the complete unchanged PostgreSQL SQL catalog and installs `psql`. SSH must use a pre-provisioned known-hosts file and `BatchMode=yes`; Docker access is limited to trusted operators. Python 3.11+ and Docker Compose v2 are required.
4. On each Docker host create a **private** `deploy/production/.env.rolling-target-0517` from its existing `.env`; the *only* change must be `LAUNCHER_API_IMAGE=<verified-0.51.7-image@sha256:digest>`. The controller compares complete rendered Compose JSON (not just declared strings) and refuses any changes to secrets, trust keys, endpoints, node IDs, network ports, volumes, Admin/ingress images, mounts or healthchecks. Keep files owner-consistent, 0600, and their directory non-group/world-writable. Do not transfer `.env` to the operator host or put credentials on argv.
5. On the operator machine create a 0600 file containing one PostgreSQL URL with `sslmode=verify-full` for the shared *writer*. The role needs read access to `schema_migrations` and information_schema and permission to obtain advisory locks. This URL is passed through the local file, not command-line credentials. No DDL may run while 0.51.6 is present. Verify all 117 migration file hashes match the pinned 0.51.5/0.51.6 catalog. Freeze other deployment tools on these hosts during the update (the PostgreSQL advisory lock is used by this controller, not by unrelated tools).
6. Before cutover, independently test an explicit real ServerBridge command, background job/outbox processing, authentication, publication, and read/write traffic on the shared dependencies. The controller performs HTTP/live dependency checks; it does **not** reproduce every application workflow.

## Per-host dry admission (does not modify containers)

On **each** host:

```sh
cd /opt/launcher/deploy/production
chmod 600 .env .env.rolling-target-0517
python3 /opt/launcher/scripts/operations/rolling_update_0517.py local-plan \
  --directory /opt/launcher/deploy/production --project launcher \
  --output /var/lib/launcher/evidence/roll-plan-$(hostname).json
```

The plan confirms the **actual** healthy 0.51.6 API/worker, validates the staged config and returns only redacted image references/digests and node identifiers. Do not proceed if any host fails. Stage the target image under the real registry digest; no mutable tag is accepted.

## промышленное развёртывание доверенным оператором

```sh
python3 scripts/operations/rolling_update_0517.py cluster-roll \
  --node a=deployer@host-a.internal --node b=deployer@host-b.internal \
  --directory /opt/launcher/deploy/production --project launcher \
  --remote-script /opt/launcher/scripts/operations/multi_host_0512.py \
  --rolling-script /opt/launcher/scripts/operations/rolling_update_0517.py \
  --edge-url https://launcher.example \
  --pg-dsn-file /secure/launcher-ha-writer.url \
  --allow-update \
  --output /secure/evidence/rolling-0517.json
```

The controller obtains one **session-scoped PostgreSQL advisory lock** and refuses concurrent runs that use the same lock. It checks every live API/worker version, signed ServerBridge v3 capability fingerprints, loader/runtime API contracts and real PostgreSQL schema shape/checksums. An external HTTPS `/ready` must pass; each host's dependency probes must succeed. It then processes one host at a time:

1. **Plan:** confirm the current live process is 0.51.6, compare exact rendered source/target Compose configurations, verify pinned image and store the already-vetted previous `.env` securely with `fsync`.
2. **Pre-pull:** fetch the 0.51.7 image by digest before disrupting any existing service; verify source and target images are present.
3. **Graceful local stop:** stop **only that host's worker and API** with a 45-second grace period. Its other ingress/Admin and **all other hosts** remain running. Docker volumes are not removed.
4. **Atomic switch:** use a private file and `os.replace` to update `.env`, record each phase in `.rolling-state-0517.json`, and `docker compose up -d --no-build --no-deps --force-recreate --wait api worker`. This is a real container recreate, not a simulated rollout.
5. **Admission:** check real runtime version 0.51.7 for both roles, complete per-host dependency growth and API/Bridge response fingerprints, the surviving peers, PostgreSQL rows/checksums, and the external public HTTPS LB. While the node changes, a background thread samples public `/ready` once per second; any sampled failure blocks success and causes a rollback of **that node** only.
6. **Continue:** only after all checks pass, repeat for the next host. The controller supports re-entry when earlier hosts are already running 0.51.7; a completed node is not restarted merely to resume after an SSH/operator failure.

**Readiness sampling is not proof of zero interrupted requests.** For a production SLO, record real client traffic, in-flight 5xx/latency, WebSocket behavior, task completion, timeouts and server joins throughout the rollout with an external load driver. A compatible control-plane update does not live-migrate Minecraft world memory.

## восстановление после ошибок и аварий

A host update which fails after creating its private backup attempts to restore the exact original `.env`, recreates only that host's API/worker from the previously pinned source image, and confirms **real** 0.51.6 readiness. It never restores a previous PostgreSQL backup and silently discards acknowledged writes. If the restart or verification fails, the host journal is marked `manual-recovery-required` and the controller returns a nonzero status; **do not** continue the rollout.

If the operator or SSH process exits unexpectedly, check the actual cluster versions and the host's state journal. If the host's journal is `stopping`, `switching` or `applied` and you need to revert that node, run on that host:

```sh
python3 /opt/launcher/scripts/operations/rolling_update_0517.py local-rollback \
  --directory /opt/launcher/deploy/production --project launcher \
  --allow-update --output /var/lib/launcher/evidence/rollback-$(hostname).json
```

The backup and journal are separate root/operator-controlled 0600 files and **must not be edited by automation during recovery**. The rollback rejects a modified source backup or a current `.env` that does not match the pinned source/target. After a `rolled-back` journal, operators must investigate, archive evidence and explicitly remove the completed journal+backup before scheduling another attempt; no automatic deletion of prior recovery evidence occurs.

If only one host is running, PostgreSQL migration checks fail, a different version is detected, the load balancer is unhealthy, the PostgreSQL advisory lock/session is unavailable, or any SSH command has ambiguous results: **BLOCKED**. Do not force the next host or manually overwrite a report. In all cases verify integrity of published builds and ServerBridge command receipts separately after the update.

## что проверено и что не проверено

- The script performs *actual* Docker Compose, SSH, SQL and HTTPS operations when connected to a real multi-host environment; its Python unit tests use controlled fixtures to verify refusals and failure paths, **not** to claim a physical multi-host PASS.
- Database migration catalog remains byte-identical to 0.51.6 (checksum pinned to 0.51.5). There is no expand/contract DDL and no independent validation of arbitrary future N/N−1 combinations.
- PostgreSQL advisory lock serializes **this** rolling controller only. It does not fence independent operators/legacy scripts, prevent nonparticipating writers, or substitute for PostgreSQL quorum and ServerBridge/world fencing.
- Final 0.52.0 HA GA requires independent physical-host failover, real network partition, real gameplay and confirmed RTO/RPO on signed final packages. A valid 0.51.7 report is an operational observation for its exact images and hosts, not that GA receipt.

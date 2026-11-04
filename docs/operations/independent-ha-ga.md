# NeverLauncher 0.52.0 — independent HA acceptance (release gate)

**Scope:** production code for executing/observing independent multi-host HA drills on real infrastructure. **Not a GA certificate by itself.** The attached source contains no physical lab, signed final packages, live credentials or independent reviewer approval. The `gate` command returns `BLOCKED` (exit code 3) until separate hardware, storage, JVM and release evidence is supplied and validated by an independent reviewer. Never treat green Python CI tests or a Docker bridge partition as physical failover acceptance.

## предварительные требования

* On a dedicated, **different machine** from all production Docker nodes, use a named non-root independent acceptance operator (`--publisher` is the primary release operator, and must differ). Use a verified source checkout with `VERSION=0.52.0` and exact `--commit` (40 hexadecimal characters); the supplied commit identifier is a claimed release identifier and must also be matched externally against signed provenance.
* Two or more independent Docker hosts running real 0.51.10 or 0.52.0 images, strict-key SSH, external PostgreSQL/Patroni, Redis, versioned S3, TLS ingress with independent load balancer, Alertmanager with live HTTPS receiver. The test tool never creates these clusters and never substitutes isolated containers for distinct machines. Do not use production customer workloads for destructive tests.
* Install `multi_host_0512.py`, `multi_host_chaos_05110.py` and `rolling_update_0520.py` on operator and Docker hosts at matching absolute paths; prepare private 0600 `.env.rolling-target-0520` for each host with *only* the target API/worker image changed to the exact immutable OCI digest. Database schema must match the unchanged append-only catalog, and both releases must have identical HTTP/Bridge contracts.
* Pre-create a **0700**, operator-owned receipt directory and an *empty* 0700 chaos suite directory. Create per-host private, scoped, unexpired 0600 network fault approvals as described in `multi-host-chaos-observability.md`. A stale or uncertain fault journal must be healed before running again. Never run chaos and rolling updates concurrently.
* Use separate staging/recovery targets for `cross_host_recovery_0519.py` and a 0.51.8 consistent cohort with real PostgreSQL WAL, S3, backups of all host volumes/worlds and an independent acknowledgement ledger. DR requires independent source fencing and restored external credentials. Do not infer world RPO or game join from an audit ledger.

## Real rolling update 0.51.10 → 0.52.0

The new `scripts/operations/rolling_update_0520.py` is a runnable copy of the previous controlled update path, with new source/target versions and **separate** journal/backup/staged-env names. It does not remove the prior 0.51.6→0.51.7 rollback procedure. With `--allow-update`, the independent acceptance CLI calls its `cluster-roll` action, which obtains a PostgreSQL advisory lock, preflights all host digests, pulls images before stop, updates one API+worker host at a time, observes the HTTPS ingress during cutover, rechecks schema/Bridge on each host and attempts node-scoped rollback on failure. Ingress/Admin/world processes are not replaced by this controller.

Example from independent operator node (replace all example hosts, URLs, commit, account and file paths):

```bash
export COMMIT=<40-hex-release-commit>
mkdir -m 700 -p /var/lib/neverlauncher-ga-0520
python3 scripts/operations/independent_ha_ga_0520.py rolling \
  --node a=ops@node-a.example.org --node b=ops@node-b.example.org \
  --directory /opt/launcher/deploy/production --project launcher \
  --edge-url https://launcher.example.org/ready \
  --pg-dsn-file /var/lib/neverlauncher-ga-0520/pg-connection.conf \
  --publisher release_operator --commit "$COMMIT" --allow-update \
  --output /var/lib/neverlauncher-ga-0520/rolling.json
```

The tool requires pre-update API/worker processes to be *0.51.10* on **all** nodes; after a successful cutover all must report *0.52.0*. The per-node `.rolling.json` receipt contains actual measured HTTPS failures and process versions; if a partial update is detected, inspect the host's `.rolling-state-0520.json` and use `local-rollback` or controlled recovery rather than trying to erase PostgreSQL data.

## Real chaos, independent alerts, recovery

Execute after rolling, on the same two or more actual target machines:

```bash
mkdir -m 700 /var/lib/neverlauncher-ga-0520/chaos
python3 scripts/operations/independent_ha_ga_0520.py chaos \
  --node a=ops@node-a.example.org --node b=ops@node-b.example.org \
  --directory /opt/launcher/deploy/production --project launcher \
  --edge-url https://launcher.example.org/ready \
  --alertmanager-url https://alerts.example.org \
  --pg-dsn-file /var/lib/neverlauncher-ga-0520/pg-connection.conf \
  --suite-directory /var/lib/neverlauncher-ga-0520/chaos --iterations 1 \
  --publisher release_operator --commit "$COMMIT" --allow-disruption \
  --output /var/lib/neverlauncher-ga-0520/chaos.json
```

This **executes** every host-stack stop and Docker network disconnect against each host via the 0.51.10 executor; requires real observable failure, five sustained ingress samples, live survivor/PG/Redis/S3 probes, actual Alertmanager alert state `ACTIVE`, verified full recovery and absence of orphan partition journals. It independently recomputes SHA-256 for every child receipt. The alert API alone does not prove downstream webhook delivery. Docker network partition is not a rack/switch partition; physically powered-off hosts and database quorum partitions must be verified independently.

For DR, first execute the *real* `cross_host_recovery_0519.py prepare` / `replay-postgres` / `admit` sequence from the 0.51.9 recovery runbook using a fresh *separate* infrastructure and a captured incident time and acknowledgement ledger. The live admission step must have completed and the recovered cluster must be running `0.52.0`. Next, from a different independent observer:

```bash
python3 scripts/operations/independent_ha_ga_0520.py recovery \
  --node a=ops@new-a.example.org --node b=ops@new-b.example.org \
  --directory /opt/launcher/deploy/production --project launcher-dr \
  --edge-url https://recovered.example.org/ready \
  --pg-dsn-file /var/lib/neverlauncher-ga-0520/recovered-pg.conf \
  --recovery-work /var/lib/neverlauncher-ga-0520/recovery-work \
  --maximum-rto 180 --maximum-sample-rpo 60 \
  --publisher release_operator --commit "$COMMIT" \
  --output /var/lib/neverlauncher-ga-0520/recovery.json
```

The controller re-reads **live** API/worker versions, migrations and HTTPS ingress, checks recovery journal and verified result from the exact new machines, and refuses missing/uncertain sampled audit RPO or excessive measured ingress RTO. Sampled audit RPO is **not** proof of world/S3/global RPO. A separate real Minecraft launch/join and world-state readback must be captured externally.

## Final downloaded payload, independent review and GA admission

First verify the **actual** six signed, final platform packages (no substituted release artifacts) with the existing binary-delivery checker and required `RELEASE_MANIFEST.json` / `DELIVERY_VERIFIED_0462.json`:

```bash
python3 scripts/operations/independent_ha_ga_0520.py bundle \
  --bundle /var/lib/neverlauncher-ga-0520/final-release \
  --publisher release_operator --commit "$COMMIT" \
  --output /var/lib/neverlauncher-ga-0520/bundle.json
```

After all four stage receipts are produced, the independent operator can run the **non-promoting** consistency gate:

```bash
python3 scripts/operations/independent_ha_ga_0520.py gate \
  --bundle /var/lib/neverlauncher-ga-0520/final-release \
  --receipt /var/lib/neverlauncher-ga-0520/rolling.json \
  --receipt /var/lib/neverlauncher-ga-0520/chaos.json \
  --receipt /var/lib/neverlauncher-ga-0520/recovery.json \
  --receipt /var/lib/neverlauncher-ga-0520/bundle.json \
  --publisher release_operator --commit "$COMMIT" \
  --output /var/lib/neverlauncher-ga-0520/ga-blockers.json
```

It binds each receipt to the same release/commit/operator and rehashes the final release files, refusing missing/duplicate/altered evidence, mismatch in host/OCI cohorts, nonzero edge failures, changed schema, missing DR result or excessive RTO. It **never promotes** the build or creates a fake GA PASS. To accept production GA, independently collect externally signed power-off, physical network isolation, quorum failover, object/DB/world reconciliation, downstream alert receipt, real game join, native signing and independent approval of the exact final bytes; run the appropriate native/platform gates as well. This 0.52.0 implementation records the blockers instead of waiving them.

## Acceptance limitations

* The version selector is **deliberately explicit**, 0.51.10→0.52.0. Do not imply a universal N/N−1 guarantee for unspecified versions, PostgreSQL DDL changes, JVM agents or game worlds.
* `rolling` accepts only a preflighted homogeneous 0.51.10 cluster. An already half-upgraded cluster requires inspection/recovery through the lower-level controller, not a second acceptance receipt.
* `recovery` checks the previously **actually executed** DR path and live recovered site. It does not itself clone volumes, promote PostgreSQL, or substitute an administrator's claim of fencing for physical machine verification.
* The independent code is Linux/operator-host oriented; six native platform signed installers must be verified separately. This archive has source changes, not final signed installers and not live machine evidence.
* No production GA or measured HA SLA is asserted from unit-test results.

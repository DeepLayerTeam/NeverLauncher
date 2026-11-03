# NeverLauncher 0.51.8 — executable consistent backup and PostgreSQL PITR

**This is a maintenance-window, write-fenced, multi-host checkpoint.** It intentionally interrupts API/worker writes and gracefully stops affected Minecraft servers; it is not an online atomic transaction across PostgreSQL/S3/game JVMs. A physical PostgreSQL backup with continuous WAL archiving provides database PITR. The cohort's S3 objects, extension state, identities and game worlds are coordinated with one recorded PostgreSQL LSN. Restoring PostgreSQL to an *arbitrary other time* is **not** a coherent S3/game-world restore.

## Provision the actual dependencies before the backup

1. At least two distinct Docker machines deployed using `deploy/production/docker-compose.multi-host.yml`, healthy PostgreSQL primary/Patroni, Redis, S3 and ingress. A trusted operator is able to SSH into the game hosts and Docker hosts with `StrictHostKeyChecking=yes` and pinned `known_hosts`. Freeze unrelated writers, third-party auth providers, all independent console/DB scripts, publishing, scheduler tasks, DB migrations, release operations and write-enabled maintenance users **outside this tool**. Block inbound writes at the external load balancer first. No second operator may resume API or restart a Minecraft JVM during the snapshot.
2. Provide `pgbackrest` with an existing working stanza `launcher`, independent encrypted offsite repository and *continuous* `archive-push` from the PostgreSQL primary/Patroni. Typical PostgreSQL requirements are `wal_level=replica`, `archive_mode=on`, and `archive_command='pgbackrest --stanza=launcher archive-push %p'`. Under Patroni, configure through the cluster's supported configuration interface, not an unmanaged edit. Use `pgbackrest --stanza=launcher check`, `pgbackrest --stanza=launcher info --output=json`, `pgbackrest --stanza=launcher verify --set=BACKUP_LABEL`, and monitor `pg_stat_archiver`/archive lag. Pin a pgBackRest version that supports `verify`. This tool executes those real commands; it does not fabricate a WAL archive.
3. All S3 gateways must serve the *same* authoritative bucket with **versioning enabled**. The operator credential needs ListObjectVersions, GetBucketVersioning, ListBucket, GetObject; file downloads via `aws s3 sync` must succeed. A split-brain S3 installation or a gateway with a divergent object index is not supported. A bucket with more than two million object versions is explicitly blocked until pagination/memory limits are raised and reviewed. Versioned deletes are captured in the recorded inventory.
4. Configure separately encrypted immutable/offsite retention **for both the pgBackRest repository and this checkpoint directory**. Use separate backup/restore credentials and a write-only or append-only protected destination; application/API credentials must not be able to erase backups. Test immutability/retention, KMS key access, emergency key recovery and restoration **outside this tool**. The local cohort directory contains potentially sensitive data and is *not automatically encrypted*.
5. Install Python 3.11+, Docker Compose v2, a digest-pinned trusted tar OCI image, `aws` CLI, PostgreSQL utilities (`pg_dump`, `pg_restore`, `psql`), pgBackRest and the **same** 0.51.8 script on the operator and every Docker/game host. The game host must have the actual NeverLauncher `nl` binary with the existing `server-bridge host world-backup` feature. Database credentials reside only in a private single-line `postgresql://...?...sslmode=verify-full` file (0600), not argv.
6. Identify all external identity providers. PostgreSQL identities/roles, sessions and extension installation state inside the NeverLauncher database are in the physical and logical copies. If an external file-backed provider owns identity state, use `--external-auth-policy included --external-source provider=/private/export.json`. For OIDC, remote SQL, HTTP auth providers or worlds outside the registered set, obtain a compatible independently consistent backup/fence **before** running or **do not claim full identity recovery**. `--external-auth-policy none` asserts that the installation has no external mutable auth data.
7. Escrow signing keys, trust roots, TLS credentials, KMS keys and recovery administrator secrets in a separate restricted, independently recoverable secret manager. Prepare a 0600 `trust-hashes.json` such as `{"manifest-signing-key":"<64-char lowercase SHA-256>"}`. This tool records only those fingerprints; it never exports actual private keys.

## Run a full checkpoint

On the trusted operator, create a 0600 `worlds-0518.json` with one entry for *every* managed Minecraft world (no missing worlds):

```json
[
  {"name":"survival","target":"gameops@game-host.example","serverRoot":"/srv/minecraft/survival","backupRoot":"/srv/launcher-world-snapshots","world":"world"}
]
```

Before starting, create `/secure/checkpoints` as a dedicated encrypted/private directory with mode `0700`. This operation will stop API/worker on every node, invoke the real Minecraft Host Supervisor stop/backup protocol on the game hosts, then run PostgreSQL physical backup plus WAL verification, logical dump, all ten per-host state volume archives, S3 versioned inventory/download/readback and file hash verification. It **does not** restart the game JVMs automatically; those must be admitted by the operator after verifying the completed checkpoint. The Go world-backup CLI now accepts `--hold-id RUN_ID`: its Host Supervisor gate stays atomically occupied from successful world copy until an explicit matching `world-backup release`, preventing a game restart between world snapshot and PostgreSQL checkpoint.

```sh
python3 scripts/operations/consistent_backup_0518.py backup \
  --node a=deployer@api-a.example --node b=deployer@api-b.example \
  --directory /opt/launcher/deploy/production --project launcher \
  --remote-script /opt/launcher/scripts/operations/consistent_backup_0518.py \
  --run-id 1234567890abcdef1234567890abcdef \
  --pg-dsn-file /secure/launcher-writer.url --stanza launcher \
  --s3-bucket launcher-production --s3-endpoint https://s3.internal.example \
  --tar-image 'alpine@sha256:<verified-64-hex-digest>' \
  --world-file /secure/worlds-0518.json --world-cli /opt/launcher/bin/nl \
  --trust-file /secure/trust-hashes.json \
  --external-auth-policy none \
  --destination /secure/checkpoints/0518-first \
  --acknowledge-maintenance
```

The actual image placeholder must be replaced by a pinned, checked OCI digest. Use a fresh 32-character hex `--run-id` per attempt; do not reuse prior journals. All private files must be regular, hardlink-free, `0600`. Operator source and destination must have sufficient free disk space; payload sizes can be larger than a database dump. Never share the local backup directory with public web services.

## What is checked, in order

- Real Compose configuration: PostgreSQL, Redis and S3 external; distinct machine identities/node IDs; same external DB/bucket and two API/worker roles. Each host persists a crash-recoverable private `.backup-freeze-0518.json` before stopping worker and API. Once all hosts are frozen, the game-host CLI requests a real stopped-world backup using the existing Host Supervisor lock/gate and creates a verified `launcher-world-backup/v1` archive. No live world file copy is accepted.
- PostgreSQL must be the active primary with **zero other SQL client sessions**. pgBackRest `check → backup --type=full → check → verify --set=LABEL` must produce **one new physical backup** with a recorded WAL start/end range. The independent `pg_dump -Fc` is parsed via `pg_restore --list` and holds identities/extension states at the frozen cohort. Changes to `pg_current_wal_insert_lsn()` during S3/local-world copying reject the backup.
- Every host contributes local state from `api_storage`, `api_backups`, `api_factory`, `api_coordinator`, `api_extensions` and the matching five worker volumes. All tar files are streamed and parsed with strict path/type checks and SHA-256. The backing S3 bucket is copied and downloaded again independently; version IDs/delete markers must remain identical during the copy. Every copied object byte is hashed. Any key missing or changing rejects publication.
- The complete new checkpoint is published by rename only after the manifest, filesystem inventory, world receipts, S3 bytes and pgBackRest repository are verified. On exit, the tool attempts to restart all API/worker roles it froze, including on failure. Failure to restart is **manual recovery required**, never PASS. External ingress admission and game starts remain under operator control.

## Verify and prepare recovery on another host

```sh
python3 scripts/operations/consistent_backup_0518.py verify \
  --backup /secure/checkpoints/0518-first --stanza launcher
```

This reads *actual* local files and invokes pgBackRest repository verification for the recorded backup. It does not attest offsite immutability, no other source writers, or that a separate backup/secret manager is recoverable.

A **cohort PG restore** writes a fresh, isolated PostgreSQL data directory with `recovery_target_lsn` set to the checkpoint's sealed LSN. It also redirects tablespaces to a new sibling path and never starts PostgreSQL:

```sh
python3 scripts/operations/consistent_backup_0518.py cohort-pg-restore-fresh \
  --backup /secure/checkpoints/0518-first --stanza launcher \
  --pgdata /srv/restore/new-pgdata --confirm 20261103-100000F
```

`--confirm` must match the physical backup label in `manifest.json`, not the example value. Restore only under a separate recovery host/user, **never** over running PGDATA or existing tablespaces. A successful command means restored disk files, **not WAL replay or application readiness**. Starting PostgreSQL, watching WAL replay until `pg_is_wal_replay_paused()` at the target, checking recovery target reached, restoring S3 to a *fresh* bucket, fencing the old cluster, restoring world snapshots and verifying UUIDs/release blobs/auth are covered by 0.51.9, not silently performed here.

For a **PostgreSQL-only arbitrary point-in-time** recovery (e.g. investigation), use `pitr-restore-fresh --target-time 2026-11-03T12:00:00Z --pg-only-reconciliation-ack` with the same arguments. Do not claim this as a multi-resource coherent restore or roll live production back over newer confirmed writes.

## Recovery from failed snapshot

If the operator process or SSH connection is interrupted, freeze journals remain in each deployment directory. Confirm each site's actual API/worker process status; to resume the exact backup operation run on that site:

```sh
python3 /opt/launcher/scripts/operations/consistent_backup_0518.py local-thaw \
  --directory /opt/launcher/deploy/production --project launcher \
  --run-id 1234567890abcdef1234567890abcdef
```

If `local-thaw` fails, leave the journal in place; restore backend connectivity, inspect Docker health, and repeat with the *same* run ID. If the operator or SSH process fails while a world is held, check the exact Host Supervisor/JVM state, then release that world's persistent gate with:

```sh
python3 /opt/launcher/scripts/operations/consistent_backup_0518.py local-world-release \
  --server-root /srv/minecraft/survival --world-cli /opt/launcher/bin/nl \
  --run-id 1234567890abcdef1234567890abcdef
```

This performs a real `nl server-bridge host world-backup release --hold-id RUN_ID`. An unknown/partial gate, wrong ID, live supervisor or running JVM must fail closed for operator investigation; do not forcibly remove the gate directory. **Do not remove recovery journals or restart the game hosts until the stale-lease/Bridge/world authority is reconciled**. Do not treat an incomplete staging directory as a backup. Take an independent encrypted/offsite copy of each completed checkpoint plus the pgBackRest repository/WAL chain under independently protected credentials.

**Acceptance boundary:** tests under `test_consistent_backup_0518.py` exercise actual file/archive bytes and mocked command boundaries; they do not test the live multiple-host Docker, actual PostgreSQL/pgBackRest/S3 encryption or independent restore of Minecraft worlds. The HA/PITR production acceptance remains BLOCKED pending the external rehearsal and 0.51.9/0.52.0 validation.

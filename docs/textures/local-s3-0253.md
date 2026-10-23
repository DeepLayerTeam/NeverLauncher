# NeverLauncher 0.25.3 — Local/S3 texture storage operations

The 0.25.3 release adds **operational storage** to the 0.25.2 secure PNG upload pipeline.
It is a local-project-only service and does not write or impersonate official Mojang textures.

## Deployment

1. Back up PostgreSQL and the existing `texture-blobs/sha256/` objects **before** upgrading.
2. Apply `services/api/internal/dbmigrate/sql/0069_texture_storage_0253.sql` using the project's normal checksum-tracked migration runner (do not replay or edit 0067/0068).
3. Deploy the 0.25.3 API. Uploads use conditional S3 `If-None-Match: *` with signed `Content-Type`, cache headers and SHA-256; collisions cause a content verification, not an overwrite. Local writes remain atomic, fsynced hardlinks.
4. Configure either `NEVERLAUNCHER_STORAGE_DRIVER=local` + `NEVERLAUNCHER_STORAGE_LOCAL_PATH`, or `NEVERLAUNCHER_STORAGE_DRIVER=s3` + the existing `NEVERLAUNCHER_STORAGE_S3_*` variables. **Do not change the driver without migrating the DB object metadata and bytes.** Backups/restores require the same driver as their snapshot.

The project-wide default limits are 20 **unique stored blobs per user** and a **10 MiB sum of normalized bytes** across their stored blobs. Existing 0.25.2 blobs referenced by assignments are charged once to the owning user at migration; two users selecting the same digest share one physical object but have separate quota accounting. `texture_project_policies` (`project_id=''`) controls `max_blobs_per_player` and `max_bytes_per_player`. Both quota checks and ownership reservation run under one PostgreSQL transaction plus a per-user advisory lock. The upload pre-registers a `staging` row and a user quota reservation **before** writing bytes. If the storage write or final assignment CAS fails, the orphan is still in PostgreSQL and will become eligible for GC after seven days; no untracked object is produced by the 0.25.3 upload handler. Objects left untracked by older 0.25.2 instances still require a separate inventory reconciliation before upgrading (do not delete objects using filename guesses).

## Offline maintenance command

Run from `services/api` with the same environment as the API and `NEVERLAUNCHER_DATABASE_DSN` set. Install/build with `go build -o texture-maintenance ./cmd/texture-maintenance-0253`.

```bash
./texture-maintenance --command backup --backup /var/backups/neverlauncher/textures-2026-10-23
./texture-maintenance --command restore --backup /var/backups/neverlauncher/textures-2026-10-23
./texture-maintenance --command gc --limit 100
```

`backup` reads the verified object inventory from PostgreSQL, fetches and SHA-256-verifies **each** local/S3 object, and writes an owner-only directory with a JSON manifest and content-addressed files. It fsyncs files and directories before atomic publish. Destination must not exist; failed backups are never published. Store the backup **off host**, encrypt it at rest, keep it separate from the storage bucket and back up PostgreSQL with your normal point-in-time recovery mechanism. A texture backup by itself is NOT a complete database backup.

`restore` requires a matching restored PostgreSQL inventory (digest, size, backend and key), verifies every file before writing, deduplicates healthy objects, and repairs corrupt objects using local atomic replacement or a signed S3 `If-Match` ETag CAS followed by a full readback. This repair is available **only** to the offline operator command, never to a public upload. Do not restore directly from an untrusted snapshot. This command does not restore accounts, assignments or the database itself.

`gc` leases at most 100 obsolete verified/quarantined blobs per invocation. To be eligible, the blob must be at least **7 days old**, have no current assignment, no project default, and no revision pointing to it in the last 7 days. A staging retry refreshes the object's last-upload timestamp to prevent GC races. The worker makes eligible objects unavailable by quarantining their DB records, deletes its object from local/S3, and removes the DB row with its associated per-user quota records. Failed deletes are retryable after release or a 15-minute lease expiration. Do not run `backup`/`restore` concurrently with GC. Run GC only after a successful offsite backup; schedule it under an operator scheduler (not automatically on API startup). Never run maintenance against a storage driver different from that recorded for each blob.

`GET /api/v1/textures/blob/{digest}` continues to return SHA-256 ETags, bounded data integrity checks, and short public caching only while assigned and public. User previews are `private, no-store`. Deleting/replacing a selection removes public serving authorization immediately, but cannot revoke copies already cached by external clients.

## Validation

```bash
cd services/api
go test ./internal/storage ./internal/texturepng ./internal/dbmigrate ./internal/model
# Full backend test needs the project's Go module dependencies:
go test ./internal/repository ./internal/httpapi
# PostgreSQL integration fixture for 0.25.3 (separate test DB):
TEST_PG_DSN_0253='postgres://...' go test ./internal/repository -run TestTextureStorageQuota0253 -count=1
```

S3-compatible backends should additionally be tested against the target vendor/MinIO, because conditional PUT semantics and versioning options vary by provider. Enable external object-versioning / replication for stronger disaster recovery; this app-level backup does not replace them.

# 0.22.8 — Transactional Sync

## Server-side invariants

- `channel_heads` owns one mutable pointer per `(project_id, profile_id, channel)` with a monotonically increasing `revision`. All release records remain immutable after publication. Migration `0060` backfills the latest published release at revision 1 without modifying or re-signing legacy Manifests.
- The HTTP package publish route and operations endpoint capture `expectedHeadRevision` when the durable job is enqueued. The value is frozen inside its idempotent job payload; queued historical jobs lacking it are rejected, not interpreted as revision zero.
- Both the direct repository publish path and durable commit use compare-and-swap. PostgreSQL locks the project before reading the head and updates `release_versions`, `channel_heads`, audit, completed job, and outbox in a **single transaction**. A stale expected revision rolls back all of those writes and returns a conflict.
- Public manifest selection joins through `channel_heads`; unpublished, superseded, or merely more recent records are not selected.
- `GET /api/v1/projects/{projectId}/profiles/{profileId}/channels/{channel}/head` provides a permission-checked head and its ETag revision. `If-Match: "N"` on direct package publish optionally asserts the operator's observed revision.
- Outbox events include `headRevision`, allowing consumers to discard stale notifications.

## Client-side invariants

- CLI package updates stage all replacement bytes, verify size/SHA-256, preserve user-owned paths, and retain rollback snapshots.
- The installed `client-state.json` content hash is captured before the update and checked **under the updater lock after recovery**. Competing updates using stale state cannot apply any new package files.
- For client-package updates, `.neverlauncher/client-state.json` is activated last, only after all managed changes and post-apply verification succeed. The version pointer is atomically replaced; on failure, the existing journal restores previous files and version state.
- `packageSha256` is stored in the activated client-state for auditing which package metadata produced the installed version.

## Operational notes and remaining limitations

- Run migration `0060` before rolling out 0.22.8 API nodes; roll out server before clients. A rollback to an API build unaware of `channel_heads` is not safe after new publication events.
- Concurrent live readers of the legacy in-place installed game tree can still see intermediate file replacements while the updater operates. The version pointer is atomic, and updater recovery is crash-consistent, but fully atomic directory-level visibility requires a separate version-directory runtime layout (not claimed here).
- A complete production certification requires API build/test dependencies, a live PostgreSQL concurrent publish test, plus Desktop/Java E2E. Unit tests alone are insufficient.

# 0.22.2 — Profile/Manifest v2: transactional snapshot integrity

## Implemented in live execution paths

- **Immutable pinned snapshot during editing and publication**: `UpdateVersionManifest` and `PublishVersionWithManifest` reject a change of schema, project/profile/release identity or a change of `profileSnapshot` (including changing only its revision while keeping a valid digest). A mutable profile may advance independently; previously created releases stay pinned to the original historical revision.
- **PostgreSQL release constraints**: migration `0057_schema_evolution_integrity_0222` validates v2 snapshots against immutable `profile_revisions_0221`, prohibits snapshot substitutions and v1→v2 rewrites of existing drafts, and prevents published manifest/status modification or deletion. The migration does not alter existing signed Manifest JSON, v1 included.
- **PostgreSQL profile head consistency**: deferred transaction constraint requires the current profile head to have an *exact* immutable history entry. This permits atomic head+history writes and rejects out-of-band changes that skip revision history.
- **Consistent snapshot acquisition**: PostgreSQL `CurrentProfileSnapshot` selects the current revision from the immutable history, joined to the profile head in a single statement, rather than reading a potentially changed head without its history.
- **Strict handling of invalid data**: reading a corrupt release fails instead of returning a partially initialized model; first-write revision CAS behavior now matches the in-memory repository.
- **No implicit signature invalidation**: the older convenience `PublishVersion` is limited to an existing signed draft. It no longer rebuilds a signed manifest with a new `createdAt` and replacement files during publishing. Normal API publishes continue through the durable signed workflow.
- **In-memory safety**: `ListVersions`, `GetManifest`, `CreateVersion`, draft update/publish and status updates isolate pointer/slice/map data from callers; a returned `ProfileSnapshot` cannot mutate the stored release by alias.

## Production migration

1. Back up the production database, audit logs and released files. Run the 0.22.1→0.22.2 migration in a staging environment first. Stop publication workers during the upgrade.
2. Deploy matching API/CLI binaries and apply migrations (PostgreSQL migration `0057`; the SQL file is mirrored in the CLI migration catalog). Existing migration `0056` must already be applied and must retain its original checksum.
3. For preflight, confirm historical records match mutable profile heads and all stored v2 release snapshots. Example checks:

```sql
SELECT count(*) AS invalid_profile_heads FROM profiles p LEFT JOIN profile_revisions_0221 h
 ON h.project_id=p.project_id AND h.profile_id=p.id AND h.revision=p.revision
WHERE h.revision IS NULL OR h.digest <> p.digest OR
 h.spec <> jsonb_build_object('projectId',p.project_id,'id',p.id,'name',p.name,
 'description',p.description,'loader',p.loader,'preset',p.preset,'isDefault',p.is_default);

SELECT count(*) AS orphan_v2_release_snapshots FROM release_versions v
WHERE v.manifest->>'schemaVersion'='2.0' AND NOT EXISTS(
 SELECT 1 FROM profile_revisions_0221 h
 WHERE h.project_id=v.project_id AND h.profile_id=v.profile_id
 AND h.revision=(v.manifest->'profileSnapshot'->>'revision')::bigint
 AND h.digest=v.manifest->'profileSnapshot'->>'digest'
 AND h.spec=v.manifest->'profileSnapshot'->'spec');
```

Expected: zero for both. If the query fails on malformed stored revision, treat this as a data-integrity incident and investigate before proceeding; do not bypass the constraints.

4. Run staging E2E against live PostgreSQL: create a v2 profile and release; edit the profile; update the release metadata; sign and validate; publish through the durable flow; attempt to mutate the snapshot and delete the published release (both must be denied). Confirm old v1 signature still verifies with its original pinned key.
5. Rollback should restore backups or use a forward fix. **Do not edit an already applied migration or downgrade the 0.22.2 binary to a version that doesn't maintain revision history**. Migration `0057` is intentionally additive and has no destructive down step.

## Compatibility and scope

No Profile/Manifest wire-version change occurs: schema version remains `2.0`. This release completes production hardening of P01, **not** P02–P10: new per-server semantics, loader constraints and workspace management remain separate milestones. Production certification additionally requires live PostgreSQL migrations, API integration, Rust-client launch verification and signed release E2E. Passing the isolated Go model/migration tests alone does not certify these.

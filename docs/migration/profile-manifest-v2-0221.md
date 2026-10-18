# 0.22.1: Profile/Manifest schema v2

## Production upgrade

1. Back up PostgreSQL and release object storage. Use the **0.22.1** API and CLI binaries together.
2. Stop publishers and background workers, deploy the updated backend/runtime clients and apply API migrations using the existing `nl db migrate apply --dsn <postgres-dsn>` command, or start the 0.22.1 API with `NEVERLAUNCHER_DATABASE_AUTO_MIGRATE=true` (verify the exact variable in `services/api/internal/config/config.go`). The `0056_profile_manifest_schema_evolution_0221` SQL file is mirrored under `cli/internal/dbmigrate/sql`.
3. Confirm `schema_migrations` has the `0056_...` checksum; check the backfill with:

   ```sql
   SELECT count(*) FROM profiles p LEFT JOIN profile_revisions_0221 r
     ON r.project_id=p.project_id AND r.profile_id=p.id AND r.revision=p.revision
     WHERE r.revision IS NULL OR r.digest<>p.digest;
   -- expected: 0
   ```

4. Upgrade desktop builds before publishing Manifest v2 to affected clients. v1 signed manifests remain accepted without modifications.
5. Verify the release pipeline in staging: create profile → create new draft → edit profile → sign draft → run validations → publish. The published manifest must contain the original immutable `profileSnapshot` revision; no profile edit may rewrite it.

## Data and compatibility guarantees

- Existing `release_versions.manifest` JSON and their Ed25519 signatures are **not changed** by the migration. There is no silent re-sign of public releases.
- Existing mutable profiles become schema v2, revision 1. Migration seeds append-only `profile_revisions_0221` with the exact backfilled metadata and sha256 digest.
- A profile edit changes the mutable head atomically with the insertion of one immutable revision row, with an optional compare-and-swap expected revision. A no-op edit doesn't increment the revision.
- New drafts use Manifest `schemaVersion: "2.0"` and freeze the current `profileSnapshot` at draft creation. Modifying the mutable profile later doesn't alter the draft snapshot. Signing covers the entire v2 payload and the desktop NeverRuntime verifies both the signature and snapshot digest.
- v1 manifests do **not** carry `profileSnapshot`. v1 serialization is unchanged, so previously signed payloads verify without re-signing.
- Unsupported manifest versions, missing v2 snapshots, changed snapshot digests, or invalid project/profile identities are rejected before signing or verifying.
- `GET /api/v1/projects/{projectId}/profiles/{profileId}/manifest` returns only published versions, not drafts. New v2 public manifests are signature-checked before being returned.
- `GET /api/v1/projects/{projectId}/profiles/{profileId}/revisions` returns immutable revision history; `?revision=N` selects exactly that revision or responds 404.

## Profile v2 wire format

`GET /api/v1/projects/{projectId}/profiles` exposes `schemaVersion`, `revision`, and `digest` on each profile. An immutable manifest snapshot contains:

```json
{
  "schemaVersion": "2.0",
  "revision": 1,
  "digest": "sha256-hex-of-profile-spec",
  "spec": {
    "projectId": "my-project", "id": "vanilla", "name": "Vanilla",
    "description": "", "loader": "vanilla", "preset": "", "isDefault": true
  }
}
```

Digest is lowercase hex SHA-256 of the seven spec values in the order `projectId, id, name, description, loader, preset, isDefault`, joined with NUL bytes, UTF-8 encoded; `isDefault` is the ASCII string `true` or `false`. Database migration and Go/Rust use the same encoding.

A profile update may supply `expectedRevision` in the PATCH request. A mismatch produces HTTP 409. Unknown schema versions fail closed. Further Minecraft, server, OS, and file policy semantics are deferred to P02–P04, and are not falsely claimed as implemented in 0.22.1.

## Rollback

The migration is additive except for normalizing existing profiles to v2. Rolling back the *binary* to 0.22.0 after creating v2 manifests is unsafe: the older Rust client cannot verify v2 snapshots, and earlier backend profile writes do not maintain the new revision table. Restore from a compatible backup or keep 0.22.1+ until clients are upgraded; do not edit already signed published manifests as a workaround. There is deliberately no destructive down migration.

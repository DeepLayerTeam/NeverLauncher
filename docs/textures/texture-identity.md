# Textures 0.25.1: canonical identity and revisioned selections

## Scope

This release persists the texture identity and selection **data plane**. It is not
PNG upload, local/S3 delivery or a complete Yggdrasil signature implementation.
Those are separately planned for 0.25.2–0.25.7. Existing URL-based textures
continue to resolve where ownership can be proven by an existing Minecraft
profile. Unmatched URLs are retained in a quarantine report, **not served**.

Minecraft identity (`minecraft_profiles.uuid`) is allocated once and preserved.
Neither the Never account ID, the launcher profile ID nor the project ID is
converted into a new Minecraft profile UUID. Session/join tickets now use the
same UUID as the local Yggdrasil profile. The `official-minecraft` realm is
separate, and this release intentionally has no endpoint capable of writing an
official texture assignment.

## Deploy / migration

1. Back up the production PostgreSQL database and the existing
   `server_bridge_textures_v2` table **before** deploying 0.25.1.
2. Deploy the 0.25.1 API binary and run the established database migration
   command for this repository, which applies `0067_texture_identity_0251.sql`
   atomically through the migration framework. Do not rewrite older migration
   checksums. PostgreSQL 14+ is required for built-in `sha256(bytea)`; deploy
   with the project's normally supported PostgreSQL 17+.
3. Confirm the migration checksum and inspect:

   ```sql
   SELECT count(*) FROM texture_legacy_unmatched;
   SELECT legacy_uuid,username,reason FROM texture_legacy_unmatched ORDER BY legacy_uuid;
   SELECT realm,profile_uuid,user_id,kind,revision,source FROM texture_assignments;
   SELECT count(*) FROM texture_assignment_revisions;
   ```

4. Records linked by exact UUID or the known `playerUUID910(user_id)` legacy
   derivation have a canonical alias and first revision. Unknown owners remain
   in `texture_legacy_unmatched` and the untouched legacy table. Creating a
   Minecraft profile for an existing account lazily resolves that account's
   deterministic alias in an atomic transaction; aliases never transfer
   ownership between accounts.
5. Rollback: stop the 0.25.1 writer and **restore the backed-up database**
   before running 0.25.0 binaries. There is no automatic down-migration;
   trying to write concurrently from both versions is unsupported. The
   original legacy table is not overwritten, but revision updates only exist
   in the new schema and would otherwise be lost after rollback.

## Operational API

All of the following require a valid Never user access token. They resolve the
**caller-owned local Minecraft UUID** server-side and require PostgreSQL.

- `GET /api/v1/me/textures` returns the current canonical profile UUID and
  all persisted assignments (`skin`/`cape`, source, visibility, revision,
  scoped IDs and active flag). The account is never selected using a query
  parameter or an arbitrary profile UUID.
- `PATCH /api/v1/me/textures/skin` or `/cape` changes an **existing** selection's
  model/visibility/active state, with an atomic revision increment and an
  audit snapshot. It cannot create external URLs or upload arbitrary content. Activating a cape also requires a positive project policy or user grant; absent policy defaults to denied.
- `GET /api/v1/me/textures/skin/history` or `/cape/history` returns up to the
  100 most recent revisions for the authenticated owner.

Example patch (revision `1` is an example: first GET the actual revision):

```http
PATCH /api/v1/me/textures/skin
Authorization: Bearer <access-token>
Content-Type: application/json

{"expectedRevision":1,"model":"slim","visibility":"private","active":true}
```

`profileUuid` may be included solely as a caller assertion; a UUID belonging
to another account yields HTTP 403. The server will **not** accept any
caller-supplied UUID as authority. Missing assignment → 404, stale revision →
409, invalid model/visibility/body → 400, unauthenticated → 401, PostgreSQL
unavailable → 503. Each committed mutation appends a revision and existing
API audit event. No fire-and-forget persistence occurs.

Public `GET /api/v1/textures/{uuid}` and local Yggdrasil now resolve the same
canonical texture selection, with aliases only for proven legacy identities.
Private/unlisted/inactive selections do not appear in the public projection.
The original URLs remain as `remote-reference` values and are **not fetched**
server-side in 0.25.1. The future SSRF-safe fetcher, PNG verification and
content-addressed local/S3 storage must be deployed before accepting new
remote or uploaded bytes.

## Diagnostics and verification

The source includes repository validation tests and an opt-in isolated
PostgreSQL integration test at
`services/api/internal/repository/textures_0251_integration_test.go`. Use an
isolated development/test database only:

```bash
cd services/api
GOPROXY=off go test ./internal/model ./internal/dbmigrate -count=1
TEST_PG_DSN_0251='postgres://.../testdb?sslmode=disable' go test ./internal/repository -run 'TestTextureIdentityAndRevisionPostgres0251' -v
```

The integration test creates a unique temporary schema and exercises legacy
migration, alias resolution, unmatched records, foreign ownership denial,
private texture suppression, monotonic revision, stale-CAS conflict, immutable
history and idempotent lazy backfill. Full Go test execution additionally
requires all `go.mod` dependencies, including `pgx`, in the build environment.

**Not included:** multipart upload/PNG decode (0.25.2), blob storage (0.25.3),
URL fetcher (0.25.4), complete user texture lifecycle (0.25.5), signature
compatibility (0.25.6), official textures (0.25.7), Desktop/Admin UI (0.25.8–9),
Gravit import (0.25.10), lifecycle/backups (0.25.11) and Minecraft E2E (0.25.12).

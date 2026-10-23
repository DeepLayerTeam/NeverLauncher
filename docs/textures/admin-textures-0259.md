# NeverLauncher 0.25.9 — Admin Texture Management

## What is deployed

**Admin → Скины и плащи** operates on the existing local Minecraft/Yggdrasil texture service, not a second storage or identity backend. The default scope (`projectId=''`) governs the global local profiles used by the current Desktop texture service. A named project scope configures assignments explicitly scoped to that project. Official Microsoft/Minecraft identities, UUIDs and capes are unaffected.

New PostgreSQL migration: `services/api/internal/dbmigrate/sql/0072_texture_admin_0259.sql`.

- Project policy with `allowPlayerSkins`, `allowPlayerCapes`, independent `defaultSkinDigest`, `defaultCapeDigest`, `fallbackSkinDigest`, `fallbackCapeDigest`, skin model `classic/slim` for default and fallback, byte quota, blob-count quota and optimistic `revision`.
- A newly created policy starts at revision 1; absence of a project-specific row is represented by revision 0 with safe defaults (skins allowed, capes denied, 10 MiB and 20 blobs).
- Explicit `allow` or `deny` exceptions for individual account **user IDs** and skin/cape kind, with `inherit` removing the exception. Pre-existing `texture_cape_grants` continue working unless overridden by a new exception. An explicit denial defeats a globally permitted cape.
- Policy and exception changes run in transactions with reason, actor ID and dated append-only history. Policy changes serialize on a PostgreSQL advisory lock and enforce expected revision. A 409 means reload and resubmit deliberately; do not retry automatically.
- Stored default/fallback digests must refer to already-verified, currently *public and active*, correctly typed managed images in the same scope. An administrator cannot publish a private user blob by guessing its SHA-256. Objects named by default/fallback are protected from texture GC. Use a legitimate local account to upload and publish an eligible texture first; select it from the Admin image list.
- Default image: returned if a player has no active selection. Fallback image: returned if the player has an active selection that cannot be publicly used (e.g. revoked by policy, private or quarantined). If fallback is not configured the regular default applies. Local Yggdrasil/ServerBridge URLs are public only for verified and explicitly published managed blobs.
- Read-only change history for actual player assignments (upload/select/reset/delete/import), scoped to a user ID and project; official Minecraft identities are never included.

**Important:** Local Desktop presently creates global (`projectId=''`) assignments. Policies for a named project govern project-scoped assignments only and do not automatically override global local/Yggdrasil selection.

## API

All routes require an authenticated Admin Bearer token with **global** `settings:manage` (project-only permission is insufficient). Both writes require a **fresh MFA session**, just like operational configuration changes. The server, not the browser, makes every authorization decision.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/v1/admin/textures/policy?projectId=` | Current policy, including CAS revision |
| PUT | `/api/v1/admin/textures/policy?projectId=` | Change project policy and record revision |
| GET | `/api/v1/admin/textures/policy/history?projectId=` | Last 100 policy changes |
| GET | `/api/v1/admin/textures/default-options?projectId=` | Public verified eligible PNG blobs |
| GET | `/api/v1/admin/textures/exceptions?projectId=&userId=` | Current user-specific exceptions |
| PUT | `/api/v1/admin/textures/exceptions/{userId}?projectId=` | Set `allow`, `deny` or `inherit` |
| GET | `/api/v1/admin/textures/exceptions/history?projectId=` | Last 100 exception changes |
| GET | `/api/v1/admin/textures/players/{userId}/history?projectId=` | Last 100 actual texture selection revisions |

**PUT policy** receives a JSON object with `expectedRevision`, `policy` and a 3–500-character `reason`. `policy` includes all booleans, four SHA-256 digest fields (empty string disables them), both skin-model fields and both quotas. Server-supplied `revision`, `projectId` and timestamps inside the policy object never authorize mutation: the scope is derived from the query and current revision from PostgreSQL.

**PUT exception** receives `kind` (`skin`/`cape`), `decision` (`allow`/`deny`/`inherit`), `reason` (3–500 characters), optionally the matching `userId`. The actual user must exist in the NeverLauncher users table, and the global capability is checked before the handler.

## Deployment and verification

1. Back up the PostgreSQL database and previously uploaded texture objects (local/S3). Deploy backend and admin files together; apply migration `0072` using the existing migration runner. Do **not** modify the sealed earlier migrations.
2. Confirm the current profile returns an existing Minecraft UUID and its previously selected managed texture without change.
3. As a globally authorized Admin, open **Скины и плащи**, select the global scope, and set a previously public verified PNG as the standard skin. Confirm a player with no skin sees it through `/api/v1/textures/{uuid}` and in a real game session.
4. Set a different fallback if desired. Revoke player skins for a controlled test user; confirm their active skin is no longer published and the fallback is used. Restore policy after the test.
5. Grant an individual cape while project capes are disabled. Then explicitly deny an account with an existing legacy cape grant and verify that the denial wins in upload, selection and public delivery.
6. Submit an outdated expected revision to the policy PUT and require HTTP 409; confirm the committed policy and history are unchanged.
7. Try to set private, non-PNG, staging, quarantined or foreign-scope digests as defaults. All must be rejected with 400. Test both local and real S3 storage for default/fallback ETag, refresh and GC retention.
8. Check that a player token, anonymous request and project-only operator cannot access any Admin texture endpoint. Validate fresh MFA rejection of an expired or unstepped-up Admin token.
9. Perform a clean Admin React/Vite build and live PostgreSQL integration test; run real Minecraft/Yggdrasil profiles before a production release.

```bash
cd services/api
TEST_PG_DSN_0259='postgres://...isolated.../database?sslmode=require' go test ./internal/repository -run '^TestTextureAdminEndToEndPostgres0259$' -count=1

cd ../../apps/admin
npm ci
npm test
npm run build
```

Production certification **is not asserted** merely because a patch archive or its offline tests exist. Confirm full API compilation, PostgreSQL migration and repository tests, live S3/local fetch and Minecraft game delivery on release infrastructure. If a rollback is necessary, restore from the pre-migration PostgreSQL backup (the new migration is additive; do not rewrite applied migration checksums).

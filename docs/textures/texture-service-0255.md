# NeverLauncher 0.25.5 — Texture Service API & Ownership

The service is implemented in the existing authenticated Backend, PostgreSQL and local/S3 storage. It manages only the logged-in user's **local NeverLauncher Minecraft identity**. An official Mojang/Microsoft Minecraft identity is never modified by this API. Desktop UX, Admin grants UI and Yggdrasil/authlib-injector signing are later 0.26 milestones.

## Database upgrade

Run the standard checksum-tracked DB migrator through migration `0071_texture_service_0255.sql` **before** deploying the API binary. This migration adds `texture_saved_items` referencing already-accounted `texture_blob_owners`; backfills verified managed images; allows a cleared, inactive assignment with no blob/URL; and extends immutable revision events with `delete`.

This is a forward-only migration. Do not revise migrations 0067–0070. Keep database and texture-storage backups before rolling out. Rollback after applying 0071 means restoring a compatible DB snapshot, not silently starting an older API binary against the new state. The content constraint forbids empty *active* selections. Resets are tombstones with retained CAS revision/history, not physical row deletion.

## Authenticated endpoints

All endpoints require a current NeverLauncher Bearer session and resolve `minecraft_profiles.uuid` from that account. The optional `profileUuid` JSON field is an assertion checked against the authenticated UUID, **never** an owner selector. All successful mutation responses contain `apiVersion` and updated `data`, with `Cache-Control: private, no-store`.

| Method and path | Request | Result |
| --- | --- | --- |
| `GET /api/v1/me/textures` | none | Canonical Minecraft UUID, both assignments and CAS revisions |
| `GET /api/v1/me/textures/library?kind=skin` | optional `skin` or `cape` filter | Up to 500 saved verified PNGs with digest, geometry, bytes, saved model and provenance |
| `GET /api/v1/me/textures/library/{kind}/{digest}/image` | no body | Private owner-only integrity-checked PNG (works while inactive) |
| `POST /api/v1/me/textures/{kind}/select` | `digest`, `expectedRevision`, `model`, `visibility`, optional `profileUuid` | Makes an already-saved, verified PNG active, records CAS revision `select` and checks kind/policy |
| `POST /api/v1/me/textures/{kind}/reset` | `expectedRevision`, optional `profileUuid` | Disables the assignment and clears blob/URL immediately; saved PNG stays in library |
| `DELETE /api/v1/me/textures/{kind}` | `expectedRevision`, optional `profileUuid` | Clears active assignment and removes its saved item (if locally managed) without erasing revisions |
| `DELETE /api/v1/me/textures/library/{kind}/{digest}` | no body | Deletes an unselected saved item, releases owner quota if no other references remain |
| `PATCH /api/v1/me/textures/{kind}` | Existing 0.25.1 selection body | Model/visibility/active changes, but cannot reactivate an empty reset tombstone |
| `GET /api/v1/me/textures/{kind}/history` | none | Up to 100 most recent immutable snapshots; includes reset and delete events |

`{kind}` is `skin` or `cape`. All digests are lowercase SHA-256. For *new* saved selection use `expectedRevision=0` if no assignment exists; otherwise use the exact latest revision returned by GET. Reset/delete require revision >= 1. `model=classic|slim` only for skins; capes require classic. `visibility=public|private|unlisted`, public means visible to the public Minecraft texture resolver; unlisted/private are not public. Client-supplied `projectId`, `userId`, `realm`, arbitrary storage key and URL are not accepted.

Example: select a previously uploaded skin from the private library:

```sh
curl -fsS -X POST "$NEVERLAUNCHER_PUBLIC_URL/api/v1/me/textures/skin/select" \
 -H "Authorization: Bearer $USER_ACCESS_TOKEN" -H 'Content-Type: application/json' \
 -d '{"digest":"<64-lowercase-hex-sha256>","expectedRevision":2,"model":"slim","visibility":"public"}'
```

Reset (retains PNG in gallery):

```sh
curl -fsS -X POST "$NEVERLAUNCHER_PUBLIC_URL/api/v1/me/textures/skin/reset" \
 -H "Authorization: Bearer $USER_ACCESS_TOKEN" -H 'Content-Type: application/json' \
 -d '{"expectedRevision":3}'
```

Deletion semantics are different from a reset. `DELETE .../{kind}` removes the *currently assigned* saved item and resets the selection; `DELETE .../library/{kind}/{digest}` removes an *inactive* saved item. Deleting an actively assigned saved item directly returns HTTP 409; reset or delete the current selection first. Deletion never overwrites another player's shared SHA-256 object and never destroys the immutable assignment history. Physical objects become eligible for the existing seven-day GC grace window only when no assignments, gallery items or project defaults reference them. GC now explicitly excludes saved library items.

## Failure modes and safety

- HTTP 401 when no usable user session; 403 for asserted foreign `profileUuid`, disallowed skin/cape policy, or denied cape grant.
- HTTP 404 for an unknown/foreign digest or missing owned assignment. Distinct error messages never reveal another account's texture.
- HTTP 409 for an incorrect `expectedRevision` or a saved item still assigned. Each assignment update and its revision event commit atomically.
- The repository checks actual ownership in PostgreSQL against `minecraft_profiles`, not just the UUID from the request. Use the same owned profile lock (advisory class 252) and per-user lock (253) as verified upload to coordinate selection, library delete, quotas and GC.
- Gallery lookup and private image serving require account ownership, verified storage status and SHA-256 validation of returned PNG bytes. Saved preview works even when not publicly assigned; its response is `private, no-store`.
- Official identities are not accepted by these operations. Cape selection is checked against project policy and a per-user grant even if a saved cape already exists. A previously reset assignment cannot be reactivated by merely setting `active=true`: choose a saved PNG first.

## Regression and release gates

```sh
cd services/api
go test -count=1 ./internal/model ./internal/texturepng ./internal/storage ./internal/dbmigrate
# Requires full Go module cache and a disposable PostgreSQL 17+ database:
TEST_PG_DSN_0255="$POSTGRES_TEST_DSN" go test -count=1 ./internal/repository -run 'TestTextureServiceOwnershipAndLifecyclePostgres0255'
go test ./internal/httpapi ./internal/repository
```

Integration test covers another user's UUID/digest, false public access after reset, revision conflicts, saved-library deletion, quota release, immutable event order, saved-but-inactive GC protection, denied/granted capes and ownership of previews. Deployment additionally requires real local/S3 storage and full Backend/UI compilation, plus an authenticated test against the running API and actual Minecraft texture refresh. Never treat passing pure Go unit tests as proof of complete production certification.

# Launcher 0.22.5 — Profile Management

## Real production execution paths

The v2 profile is stored in the existing `profiles` table and append-only
`profile_revisions_0221` history. Clone, import and preset creation all call
`CreateProfileExclusive0225`: a separate insert transaction for PostgreSQL or
one profile mutex critical section for MemoryRepository. A duplicate ID returns
HTTP 409 **without modifying the existing profile**. A SQL transaction records
profile head and revision 1 together, rolling both back on error. No schema
migration is needed: published v1/v2 manifests remain intact.

Administration UI → **Profiles → Управление профилями** supports selecting a
source profile in the grid, cloning a selected revision, downloading an export,
importing a `.json` export, comparing revisions and creating a new profile from
a preset. Permissions are checked server-side using project:write for all
operations; each creation writes an audit event.

## API examples

For the following examples the operator must be authenticated and authorized
for `project:write` on `demo-project`.

- `POST /api/v1/admin/projects/demo-project/profiles/vanilla/clone`
  JSON `{"id":"vanilla-copy","name":"Vanilla copy","sourceRevision":1}`.
  Omit `sourceRevision` to clone the current immutable profile revision.
- `GET /api/v1/admin/projects/demo-project/profiles/vanilla/export?revision=1`
  downloads JSON containing `{"format":"launcher.profile.v1", "snapshot":{...}}`.
- `POST /api/v1/admin/projects/demo-project/profiles/import`
  JSON `{"id":"imported","name":"Imported","bundle":<exported JSON object>}`.
- `GET /api/v1/admin/projects/demo-project/profiles/vanilla/diff?fromRevision=1&toRevision=2`
  returns a field-by-field comparison. Without query parameters, compares
  the penultimate revision with the latest; another profile can be selected with
  `againstProfileId`.
- `GET /api/v1/admin/profile-presets` lists supported preset metadata.
- `POST /api/v1/admin/projects/demo-project/profiles/from-preset`
  JSON `{"id":"forge-new","presetId":"forge"}`. An optional `name` overrides
  the preset's displayed name.

Presets initialize profile metadata and loader selection (`vanilla`, `fabric`,
`quilt`, `forge`, `neoforge`, or `vanilla-lite`). They do not automatically
install or publish a Minecraft build. Files and signatures are still supplied
and checked by the existing release pipeline; workspace scanning/build is P06.

## Security and compatibility

- The export format is allowlisted to immutable `ProfileSpec` public metadata.
  It cannot carry project roles, access grants, secrets, keys or signed releases.
- Source snapshots and SHA-256 digests are validated before clone or import;
  changing an exported spec without its digest is rejected.
- Import copies loader/preset/description but assigns **new ID, project ID,
  name, digest and revision**; `isDefault` is forced to `false` to prevent
  silently overriding the project's default profile.
- New profile IDs have a strict identifier grammar. Unknown JSON properties
  are rejected. Invalid or missing source revisions return an error.
- No old signed manifest is altered. Changes to the source after cloning do
  not affect the destination; editing the destination creates its own history.
- Restoring a previous revision does not rewrite history; copying it to a new
  profile ID is supported with clone and `sourceRevision`.

## Verification

With Go installed and dependencies available, run:

```bash
cd services/api
go test ./internal/model ./internal/repository ./internal/httpapi
```

The isolated `model` and `repository` suites can run offline with
`GOPROXY=off go test -tags launcher_nopgx ./internal/model ./internal/repository`.
The nopgx build tag excludes the PostgreSQL driver; it cannot certify SQL
behavior. Before declaring a production GA, additionally run full API tests,
PostgreSQL integration tests (including parallel conflicting profile inserts),
Admin `npm run build` and browser E2E against authenticated backend. Never use
the offline build tag for production binaries.

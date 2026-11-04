# Build Workspaces (0.22.6)

The Build Workspace handles real directory uploads, scans, per-file SHA-256,
base-version diff, stage selection, publication validation, and creation of an
actual release in the existing package pipeline. The old Release Workspace
remains available to resume releases created before 0.22.6.

## Workflow

1. `POST /api/v1/build-workspaces` with `projectId`, `profileId`, `channel`,
   `version`, and `settings` containing `minecraft`, `runtime`, optional
   `directories`, `fileRules`, and `toolVersions`. A v2 profile revision/digest
   is pinned; the API's tool version is authoritative.
2. Import each file with `POST /api/v1/build-workspaces/{id}/files` using
   multipart `file`, `path`, `ownership`, and *current* `revision`. The Admin UI
   accepts entire local directories via the browser's directory picker; no
   server-side arbitrary directory paths can be supplied.
3. `GET /scan` streams the stored source blobs and checks size and SHA-256.
   `GET /diff?baseVersionId=<published-id>` compares against another published
   version of the same project/profile.
4. `POST /stage` with `revision` and `paths` selects the exact files to
   include. Any import invalidates prior staging.
5. `GET /validate` checks source content, profile revision, file rules,
   Java constraints and launch metadata; reports a deterministic build digest.
6. `POST /build` with the current `revision` materializes real package files
   in configured Storage and creates/updates the corresponding draft Manifest
   v2. A partial build may be resumed; it cannot claim someone else's package.
7. Use existing `/packages/{id}/validate`, `/sign` (phishing-resistant step-up),
   `/stage`, `/integrity-check`, signed runtime evidence, and the durable
   `/operations/validate` → `/operations/execute` publish flow. **Build never
   circumvents signature, validation policy, or MFA.**

## Reproducibility and security

The `buildDigest` is SHA-256 over canonical JSON of project/profile, frozen
profile digest/revision, channel/version, settings, tool versions and sorted
selected files, with path, SHA-256, size, ownership, executable and target OS.
Release timestamps and signing timestamps are intentionally not part of this
identity. JSON serialization uses the standard Go encoder (sorted map keys).

Sources live under per-workspace content-addressed AES-256-GCM encrypted
object keys. Encryption is bound to project/workspace/content digest and uses
a domain-separated key derived from the production manifest signing secret.
Workspace paths are excluded from the public file delivery route. Rotating
the signing key invalidates unbuilt workspace source objects; finish or recreate
in-progress workspaces as part of key rotation. Only safe relative game paths are
accepted; saves, screenshots, resource packs, allowed settings and other
protected user-owned paths cannot be uploaded as managed content. API scopes
`release:prepare` and `file:write` are checked separately. CAS revisions guard
concurrent edits. SQL state persists across restarts with migration `0059`.

Operational limits: 25,000 entries per workspace and configured per-file
`StorageMaxUploadBytes` (default 512 MiB). Successful validation checks full
SHA-256 of every staged object. Missing/changed objects block materialization.
Workspaces themselves are not exposed to unauthenticated clients and cannot
publish a signed release without the existing independent authorization flow.

## Compatibility

Migration `0059` adds a new table and does not alter existing releases,
profiles, manifests or their signatures. A new workspace does not mutate its
pinned profile snapshot. Operators must run migrations before enabling routes.

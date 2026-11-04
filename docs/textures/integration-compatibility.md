# Launcher 0.25.12 — Texture Integration & Compatibility Certification

This update ships **executable** PostgreSQL/GC concurrency hardening, a live
Yggdrasil/authlib-injector profile + PNG verifier, a real S3 lifecycle test and
an automated CI matrix. It does **not** assert that Minecraft gameplay has
been certified on any platform where the game was not launched.

## Upgrade / operational change

- Deploy Backend, the maintenance binary and UI from **the same 0.25.12 build**.
  Apply the existing migrations 0067–0074. **There is no 0075 migration**: the
  changes in 0.25.12 strengthen transactional use of the existing schema.
- Stop older `texture-maintenance` GC workers during the rollout. The new
  command holds `FOR UPDATE` on the blob row through physical deletion and the
  final PostgreSQL delete. It checks active assignments, saved library items,
  project defaults/fallback, seven-day history and active backup pins while
  holding the lock. An FK-based write must wait; if storage deletion fails, DB
  state rolls back. Do not mix older workers with 0.25.12 GC.
- Use a dedicated PostgreSQL account with only the required maintenance access
  and keep local/S3 endpoint credentials out of the report and source tree.
- Keep periodic **PostgreSQL and texture object backups together**. A PNG-only
  snapshot is not sufficient to rebuild ownership, assignments or revisions.

## Reproducible verification commands

From the repository root:

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
cd services/api
go test -race -count=1 ./internal/storage ./internal/texturepng ./internal/texturefetch ./internal/yggdrasiltexture ./internal/officialminecraft ./cmd/texture-compat-02512
go build -o /tmp/texture-compat ./cmd/texture-compat-02512
go build -o /tmp/texture-maintenance ./cmd/texture-maintenance-0253
```

For **real PostgreSQL integration**, set all the appropriate
`TEST_PG_DSN_0251`, `_0252`, `_0253`, `_0254`, `_0255`, `_0259`, `_02510`,
`_02511` environment variables to a **disposable PostgreSQL 17+** database.
Never point tests at production: the tests create and drop schemas. Run:

```bash
go test -race -count=1 -timeout 12m ./internal/repository ./internal/httpapi
```

The 0.25.12 test specifically validates that a second SQL session cannot add
an FK reference while the GC worker has locked the blob row for deletion. It
also checks a failing storage callback, stale lease and replay rejection.

For **real S3**, supply `TEST_TEXTURE_S3_ENDPOINT_02512`,
`TEST_TEXTURE_S3_BUCKET_02512`, `TEST_TEXTURE_S3_ACCESS_KEY_02512`,
`TEST_TEXTURE_S3_SECRET_KEY_02512` to an isolated disposable bucket, then run:

```bash
go test -race -count=1 ./internal/storage -run TestTextureRealS3Lifecycle02512 -v
```

That test really creates an immutable object, repeats conditional PUT, checks
its digest, makes a backup, deletes with an ETag precondition, restores from
snapshot and verifies the recovered bytes. CI provisions MinIO. The test skips
with **no successful certification claim** when no S3 endpoint is configured.

Desktop and Admin verification:

```bash
(cd apps/desktop && npm ci && npm run test:textures && npm run build)
(cd apps/admin && npm ci && npm test && npm run build)
```

## Probe a running Yggdrasil/authlib-injector deployment

Select a **local Launcher Minecraft UUID** with an active public, managed
PNG skin. Set a production HTTPS API origin and run:

```bash
cd services/api
go run ./cmd/texture-compat-02512 \
  --origin https://launcher.example.com \
  --uuid 12345678-1234-4234-9234-0123456789ab \
  --expect-skin=true --expect-cape=false
```

The tool checks:

1. Live root metadata: a usable RSA public key of at least 2048 bits and a
   domain allowlist containing the server origin.
2. Live `sessionserver/session/minecraft/profile/{uuid}?unsigned=false`
   response, profile ID/name, exactly one `textures` property and its real
   RSA/SHA1withRSA signature against the key advertised in metadata.
3. Signed Base64 payload matching that same local profile and valid `slim`
   versus default metadata; official Minecraft UUIDs are not substituted.
4. Actual managed PNG requests restricted to the same API origin, digest path,
   no redirects, no URL query/userinfo, a 4 MiB response limit, SHA-256 match,
   full PNG chunk validation, decompression and Minecraft geometry.

The tool outputs a single JSON result only on success and exits non-zero on
any compatibility failure. `--expect-cape=true` makes a published local cape
mandatory. A literal loopback test server can use `--allow-loopback-http`, but
production should **never** use that flag or disable certificate validation.

This probes protocol responses and bytes, **not** a real game render. It does
not authenticate Microsoft accounts, launch Minecraft, or override allowlists.

## CI gates

`.github/workflows/texture-certification-02512.yml` includes:

- Complete Go API/maintenance/Gravit importer builds and race/vet checks with
  a **real PostgreSQL 17** container, all texture-integration test DSNs set.
- **Actual MinIO** conditional-write, object lifecycle and recovery run.
- Desktop and Admin npm test + production frontend build.
- Optional operator-initiated live HTTPS signed-profile + PNG compatibility
  probe (workflow_dispatch inputs: `texture_origin`, `local_minecraft_uuid`).

The live probe is optional for general PRs because a real deployment does not
exist for each checkout. **For release certification** it must be run on the
release candidate and its successful log recorded. Do not mark a skipped job
as an executed real-service test.

## Outstanding release gates: must be executed before 0.26.0 GA

These require actual owned accounts/hardware and **cannot** be certified from
repository unit tests or mock services:

| Test | Required evidence |
| --- | --- |
| Local account (Vanilla, Fabric and NeoForge, supported Minecraft/Java versions) | Real launch, the skin/cape visible to a second client, screenshot and logged session/profile IDs without tokens |
| `classic` and `slim` | Correct limbs in-game after model changes; verify fresh session and reconnect |
| Desktop on Windows, macOS and Linux | Screenshots of gallery, 2D/3D preview, progress, upload/cancel/select/reset/delete, 409 conflict, failure handling |
| Official Microsoft account | End-to-end OAuth login on an owned account; official skin upload/reset and selecting only owned capes; no local identity or signature reuse |
| Privacy & authz | Foreign UUID, foreign texture digest, revoked cape permission, invalid PNG, large PNG, private texture and forbidden URL blocked |
| Real non-emulated object storage | Test target S3 provider's ETag/conditional DELETE, backup recovery and cache invalidation with a published skin |
| Failure recovery | PostgreSQL and object snapshot restore from a matching checkpoint; old GC workers disabled, no dangling library references |

**Release status is not 'certified' until these observations are actually
recorded**. CI passing is necessary but does not prove the full cross-platform
Minecraft gameplay matrix. Never store live authentication tokens, RSA private
keys or personally identifiable data in workflow artifacts.

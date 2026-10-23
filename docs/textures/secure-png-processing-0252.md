# 0.25.2 — Secure PNG Processing

## Implemented

The authenticated `POST /api/v1/me/textures/{kind}/upload` accepts a **single**
`file` multipart part with `expectedRevision`, optional `model`, `visibility`
and optional `profileUuid` assertion. The Minecraft identity is **always**
resolved from the user's authenticated session. The verified PNG is normalized,
stored using SHA-256 as its key and assigned atomically in PostgreSQL.
The existing `texture_blobs` metadata and revision system are used without
creating a competing set of identities or overwriting legacy URLs.

- File body: <= 4 MiB; total multipart body: <= 4 MiB + 16 KiB.
- Decoding: full PNG decoding **after** checking all chunks' CRCs, ordering,
  completion and rejecting APNG and unknown critical chunks; no trailing bytes.
- Memory and decompression bounds: <= 1,048,576 decoded pixels, <= 1024px on
  either axis; geometry must be an integer scale of original Minecraft texture:
  skin 64×64 (classic/slim), legacy skin 64×32 (classic only), cape 64×32,
  or corresponding integer high-resolution multiples up to the pixel limits.
- Normalization: deterministic NRGBA PNG encoding with ancillary metadata
  discarded and fully transparent pixel color channels set to zero.
- Storage: normalized content digest is the object key. Local writes use a
  same-directory fsynced temp file followed by atomic hard-link, never exposing
  partial PNGs; the configured existing S3 backend is also supported.
- Database: only verified blobs are referenced; transaction enforces server-
  proven UUID ownership, per-project upload policy, a single-object size
  limit, and optimistic revision CAS (`0` means create-only; otherwise update
  the current revision). Changes are recorded in history and audit events.
- Reads: `GET /api/v1/me/textures/{kind}/image` previews an owner's managed
  texture, even when private. `GET /api/v1/textures/blob/{sha256}` serves only
  a referenced **active public** blob. Both verify bytes against SHA-256;
  private views use `no-store`, public views revalidate after 60 seconds.
  Content is served as PNG with `nosniff` and quoted ETag. The public endpoint
  is only for published textures, not a way to enumerate private uploads.

## Example

Get the current CAS revision from `GET /api/v1/me/textures`, then:

```bash
curl -fS -X POST "$NEVER_API/api/v1/me/textures/skin/upload" \
  -H "Authorization: Bearer $PLAYER_TOKEN" \
  -F 'expectedRevision=0' -F 'model=slim' -F 'visibility=public' \
  -F 'file=@skin.png;type=image/png'
```

For replacement, use the `revision` returned by the previous upload or read.
If a legacy URL-based assignment exists its revision starts at `1`, not `0`.
A stale revision returns **409**, a disallowed cape returns **403**, malformed
PNG returns **422**, and size-limit violations return **413**.

## Deployment

1. Back up PostgreSQL and the existing storage root / S3 bucket. Configure a
   **persistent** storage volume or bucket; loss of this data is not repaired
   by only restoring database metadata.
2. Apply immutable migration `0068_texture_upload_0252.sql` through the
   ordinary migration engine before routing traffic to 0.25.2.
3. Ensure `Config.PublicURL` is the correct public HTTPS API origin; the
   canonical Yggdrasil texture URL points to `/api/v1/textures/blob/{sha256}`.
4. Test a valid skin upload, read, replacement, stale CAS, foreign user,
   denied/granted cape, malformed PNG, compression bomb, private preview,
   and read from your **configured** local/S3 storage. Run PostgreSQL tests
   with `TEST_PG_DSN_0252` in an isolated test database.

## Explicit remaining work

0.25.2 implements secure ingestion and delivery; it does **not** claim full
T03 quotas, S3 object lifecycle/cleanup, backup restore certification,
revocation of already cached public images, official Minecraft texture APIs,
Yggdrasil RSA signatures, Desktop 3D preview or Admin entitlement UI.
A failed DB commit can leave an unreferenced content-addressed object until
T03 garbage collection. Public images may remain in an upstream cache for up
 to 60 seconds when changing visibility. Configure CDN rules accordingly.
The 0.25.6 protocol-compatibility release must separately certify that the
Minecraft client accepts the resulting texture property and signature format.

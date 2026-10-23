# NeverLauncher 0.25.6 — Yggdrasil/authlib-injector texture signing

## Production deployment

Generate a persistent RSA private key separate from the **Ed25519 release manifest keys**:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/neverlauncher/yggdrasil-rsa.pem
chmod 600 /etc/neverlauncher/yggdrasil-rsa.pem
```

Set `NEVERLAUNCHER_YGGDRASIL_RSA_KEY_FILE` to its absolute path on **each replica** and distribute the **same key** securely to all API instances. Do not commit the PEM to git, bake it into an image, serve it over HTTP, or place it in `NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY`. File must be a non-symlink regular file with mode 0600, PKCS#1 or PKCS#8, unencrypted RSA >= 2048 bits. Rotate only as a coordinated deployment: changing the public key invalidates cached metadata/profile signatures. Restart replicas when changing the file. If no key is configured in production or key loading fails, metadata and signed texture profile endpoints return 503 rather than unsigned properties.

Set `NEVERLAUNCHER_PUBLIC_URL` to the public HTTPS API origin. `skinDomains` automatically includes its exact hostname. For a CDN that mirrors the *same normalized digest paths*, optionally set `NEVERLAUNCHER_YGGDRASIL_TEXTURE_DOMAINS` to a CSV of explicitly trusted hosts, e.g. `textures.example.org,.cdn.example.org` (leading dot allows subdomains only). `*`, IP literal, invalid domain and scheme are rejected. Only immutable `/api/v1/textures/blob/{64-hex-sha256}` URLs are signed; raw legacy external URLs are omitted and must first pass through the bounded secure import pipeline. A texture URL on a host outside the whitelist is also omitted from signed profile attributes. Prefer managed SHA-256 texture URLs (`/api/v1/textures/blob/{digest}`) to avoid client cache staleness. Imported PNGs must have gone through the secure texture pipeline.

## Endpoints

* `GET /` — authlib-injector metadata with PEM `signaturePublickey` and `skinDomains`. 503 when signing unavailable.
* `GET /sessionserver/session/minecraft/profile/{uuid}?unsigned=false` — RSA PKCS#1 v1.5 SHA-1 signed `textures`. Default `unsigned=true` returns property without the signature as specified.
* `GET /sessionserver/session/minecraft/hasJoined` — includes signed `textures` when an eligible one-time join ticket exists.
* `GET /api/v1/minecraft/profile` and `POST /api/v1/minecraft/session` — also include correctly signed textures for the local identity.
* `POST /api/profiles/minecraft` — bounded batch lookup of profile names (max 100; no private account data).
* `PUT /api/user/profile/{uuid}/{skin|cape}` — Minecraft Bearer token, multipart `file` as image/png, optional skin `model` (`slim` or empty); validates image and owner, persists through staging/quotas/SHA-256 and returns 204.
* `DELETE /api/user/profile/{uuid}/{skin|cape}` — clears the active texture with the same Minecraft token and returns 204.
* `GET /api/v1/textures/blob/{sha256}` — serves content-addressed normalized PNG with `image/png` and SHA-256 ETag.

`textures` is Base64(UTF-8 JSON) containing Java epoch-millis `timestamp`, unhyphenated Minecraft `profileId`, `profileName`, and `SKIN`/`CAPE` URLs. `slim` is an explicit metadata model; classic omits metadata (the wire default). The signature is **SHA1withRSA** (legacy protocol requirement, not a general-purpose recommended algorithm), computed on the *Base64 property value bytes*, verifiable with the metadata RSA public key. No official Minecraft identities are re-signed or substituted.

The non-production in-memory RSA key is created once per process and must not be used for persistent real-server sessions or load-balanced deployments. Production uses stable configured key files. Set a single consistent `NEVERLAUNCHER_PUBLIC_URL` across replicas.

### Verify

```sh
curl -fsS https://your-api.example/ | jq '.skinDomains,.signaturePublickey'
curl -fsS 'https://your-api.example/sessionserver/session/minecraft/profile/LOCAL_UUID?unsigned=false' | jq '.properties'
```

For a full Minecraft compatibility certification, run a client with authlib-injector pointed at the API root and verify signed texture downloads in-game, including change of digest after replacing skin, 204 on unknown profiles, and replay rejection on hasJoined. These real-game tests have not been run in the archive authoring environment.

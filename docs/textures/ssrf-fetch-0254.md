# NeverLauncher 0.25.4 — SSRF-Safe Texture Fetcher

**Scope:** authenticated, local NeverLauncher Minecraft profiles only. Official Minecraft identities are not writable by this feature.

## HTTP import (implemented in the existing backend)

`POST /api/v1/me/textures/{kind}/import` (`kind` = `skin` or `cape`) requires an authenticated Bearer session. Send one JSON object with `url`, `expectedRevision` (0 to create, latest revision to replace), optional `model` (`classic` or `slim`, capes must be `classic`), `visibility` (`public`, `unlisted`, `private`), and optional `profileUuid` owner assertion. An assertion for another player's UUID fails before any remote network request. No arbitrary player UUID is accepted as the authorization identity.

Example (using your real HTTPS image URL and a valid token):

```bash
curl -sS -X POST "$NEVERLAUNCHER_PUBLIC_URL/api/v1/me/textures/skin/import" \
  -H "Authorization: Bearer $USER_ACCESS_TOKEN" -H 'Content-Type: application/json' \
  --data '{"url":"https://textures.example.org/skin.png","expectedRevision":0,"model":"classic","visibility":"public"}'
```

The backend validates the request and imports a PNG into **immutable SHA-256 local/S3 storage**. It never redirects clients to the original remote URL. Both URL import and multipart upload share the same 0.25.3 staging, quota, ownership, CAS, checksum, and assignment logic. Imported assignments have `source=managed-url-import` and an immutable `event=import` revision; no original remote URL or remote response headers are stored in the assignment.

## Fetch safety, enforced at execution time

- Only `https` with a DNS hostname and port 443; no literal IPs, credentials, fragments, host trailing dots, non-ASCII/invalid DNS labels, or alternate schemes and ports.
- DNS is resolved by the server and **all** returned addresses are checked against private, loopback, link-local, unspecified, carrier NAT, documentation, reserved, IPv4-mapped IPv6 and transition/resolver-special prefixes. Requests with mixed public/private A or AAAA answers fail closed.
- The TCP dial uses only a checked **numeric IP**, never the domain again. The TLS certificate is verified against the original hostname, using the normal system trust store. Proxy environment settings are ignored, so no `HTTP_PROXY`/`HTTPS_PROXY` forwarding can bypass validation.
- Redirects are not followed, even to another HTTPS hostname. No source cookies, authorization, custom headers or remote credentials are forwarded. Encoded/compressed responses are rejected.
- Max URL 2048 bytes, JSON request 4096 bytes, HTTP body 4 MiB, 1024×1024 maximum decoded PNG, 12 s total timeout, 3 s dial timeout, 4 s TLS handshake and 5 s response-header limit. Full PNG parsing/CRC/geometry validation and normalization reuses `texturepng.Process`.
- Per-server instance controls: at most 8 concurrent remote fetches and at most 5 import attempts per account per minute. Configure equivalent **shared** ingress/rate limits for multi-replica deployments.
- Remote response bodies and URL/network errors are not reflected to users. Rejection statuses: 400 unsafe URL, 413 too large, 422 invalid PNG or prohibited redirect/encoding, 429 capacity/rate limits, 502 upstream fetch failure. Ownership and policy failures use the existing 403/409 response conventions.

## Configuration and roll-out

Optional variable: `NEVERLAUNCHER_TEXTURE_FETCH_HOST_ALLOWLIST=textures.example.org,cdn.example.org`. Hosts match exactly, no wildcards or subdomain matching. An empty value permits public HTTPS DNS hosts; the blocklist and numeric-IP check **always** apply. A malformed configured allowlist disables all imports. Docker Compose passes this variable into the API container.

Apply migration `0070_texture_fetch_0254.sql` using the checksum-tracked migrator; it extends only the permitted assignment provenance and revision event enums (implemented as PostgreSQL CHECKs). Never modify previous migrations.

A strong deployment additionally restricts outbound API container egress with an independent network firewall. A public-IP filter is not a substitute for network-layer egress rules, particularly if an upstream network translates traffic.

## Tests / release validation

```bash
cd services/api
go test -count=1 ./internal/texturefetch ./internal/texturepng ./internal/storage ./internal/dbmigrate
# Requires project's Go dependencies and a test PostgreSQL instance:
go test ./internal/httpapi ./internal/repository
```

`texturefetch` tests include TLS hostname verification, actual HTTPS response/PNG normalization through a local TLS server with **controlled dial hooks**, DNS mixed-answer rebinding rejection, IP ranges, HTTP redirects, unsupported MIME/content-encoding, oversized streamed responses and malformed images. These local TLS simulations do **not** authorize loopback addresses in production. External DNS, deployment egress firewall, actual Postgres migration and real S3 remain integration release gates.

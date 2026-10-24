# NeverLauncher 0.26.8 — Never ↔ Official Minecraft Identity Linking

## Production behavior

Linking is an **explicit and independent** operation; merely signing in to Microsoft or selecting a Minecraft account in the OS vault does not create a Never identity link.

1. Log in to NeverLauncher recently (within 15 minutes of authentication). A verified, non-disabled Never user and valid session bearer are required.
2. Sign in to the *official Minecraft Java account* with the native Microsoft → Xbox → XSTS → Minecraft authentication chain. Legacy Backend tickets cannot be used to link; reauthenticate using the native flow.
3. Select the intended account and press **Привязать к Never**. Read the displayed UUID and confirm. The UI never receives Microsoft or Minecraft tokens.
4. Rust validates the selected UUID again with Minecraft Services while the native account selection mutex is held. Rust sends the selected Minecraft bearer to the authenticated Never Backend **only over HTTPS** (loopback HTTP is allowed during local development). It does not return that bearer to renderer.
5. Backend independently requests `GET https://api.minecraftservices.com/minecraft/profile` with that bearer. Only if the Java UUID is valid and equals the explicitly chosen UUID does it atomically insert/update the link in PostgreSQL, keyed by official UUID and Never user ID. A Minecraft UUID is globally unique; another Never user receives HTTP 409. Existing owners may revalidate and refresh the name.
6. UI displays the durable server link state separately from local account state. If the Backend is unavailable, the UI displays **Связи Never недоступны**, never falsely "not linked".

## Endpoints

Authenticated, Never identity scoped:

- `GET /api/v1/minecraft/official/link` — list *only* current Never user's verified links.
- `POST /api/v1/minecraft/official/link` — native-only proof of Minecraft ownership: `{ "minecraftAccessToken": "<native-only>", "expectedUuid": "<32hex>", "confirm": true }`. Requires recent Never login. No provider tokens are stored. This API is not a renderer or general third-party login API.
- `DELETE /api/v1/minecraft/official/link/{minecraftUuid}` — current owner only, requires recent Never login and confirmation in Desktop; deletes the durable Never link, **not** native credentials or upstream Microsoft session.

All responses include `Cache-Control: no-store`. POST accepts at most 12 KiB and only strictly specified JSON fields. Token text is never serialized into error responses, audit events, game arguments, or CI output by linking code.

## Persistence and deployment

The checked migration `0075_official_never_identity_0268.sql` creates `official_never_identity_links_0268`, with a foreign key to Never `users`, unique Minecraft UUID ownership and owner lookup index. It is part of normal checksum-verified database migration application. **Apply migrations before enabling upgraded Desktop clients.** In-memory-only Backend mode deliberately responds HTTP 503 instead of inventing a non-durable identity link. Database errors fail closed.

A user can link multiple separate Minecraft Java accounts. A Minecraft UUID cannot be silently claimed by a different Never user; owner must explicitly unlink. Local logout and Minecraft account removal do not delete the server link. Never account deletion cascades its links through the database foreign key.

## Release gates / real verification

- Migration upgrade and rollback procedures reviewed on an isolated PostgreSQL instance.
- Rust/Tauri compiled and tested on Windows/Linux/macOS, including OS vault, cancellation and account switching.
- Native Device Code and system-browser authorization with the project-owned approved Microsoft Client ID, followed by real Java profile verification.
- PostgreSQL unique-owner race tests and negative cases: already-linked UUID, wrong UUID, revoked Minecraft bearer, stale Never login, offline Backend, foreign-user unlink attempt.
- Audit that HTTP access logs and crash reports do not collect request bodies or Authorization headers. The Backend temporarily processes the Minecraft access token only to query Minecraft Services. Do not deploy an untrusted reverse proxy that logs bodies.

**Not a substitute for external Minecraft provider approval or actual online-mode authentication.** Neither a successful unit test nor a local credential is evidence of real online-mode join.

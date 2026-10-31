# Launcher 0.25.7 — Official Minecraft Integration

## Implemented (not a local-Yggdrasil impersonation)

Launcher 0.25.7 offers an **independent** Minecraft Java integration:
Microsoft OAuth 2.0 device-code authorization → Xbox Live → XSTS → Minecraft
Services token → the real Minecraft Services `/minecraft/profile` of that
Microsoft account. The `/minecraft/profile` endpoint must return a UUID/name;
being logged in to Microsoft or Xbox **alone is not sufficient** to create a
Minecraft Java profile. Game Pass accounts can have an accessible profile without
ordinary purchase-entitlement items, so the verified live Minecraft profile is
used as the eligibility criterion.

The official session is different from the Launcher login. Login requires
a valid current Never session and **separate user confirmation at Microsoft**.
Launcher local UUIDs, textures, skin signatures, custom profile IDs,
ServerBridge ownership and Yggdrasil RSA keys are never reused for official
accounts. OAuth client ID is the registered *public* Microsoft identity
application; this implementation does not require or retain its client secret.

### Configuration

Set `LAUNCHER_MINECRAFT_MICROSOFT_CLIENT_ID` to the application ID of an
Azure/Microsoft identity app configured for *personal Microsoft accounts* and
public-client/device-code authentication. Consent must support the `XboxLive.signin`
and `offline_access` scopes. Ensure production `LAUNCHER_AUTH_TOKEN_SECRET`
is random, at least 24 bytes, and **identical across API replicas** (the
recommended value is a random 32+-byte secret). Use HTTPS for Launcher.
The API has a fixed allowlist of outbound origins, all Microsoft/Xbox/Minecraft;
there are no caller-provided URLs. API-to-Microsoft redirects are disabled and
all responses are capped to 1 MiB with finite timeouts.

### Authenticated API usage

All endpoints require the **Never** `Authorization: Bearer <never-access-token>`;
a local Yggdrasil Minecraft bearer **must not** be used here.

| Operation | Method / path | Additional authorization |
|---|---|---|
| Start device login | POST `/api/v1/minecraft/official/device/start` | Never session |
| Poll Microsoft login | POST `/api/v1/minecraft/official/device/poll` | `X-Official-Minecraft-Session: <flow>` |
| Read official skins/capes | GET `/api/v1/minecraft/official/profile` | encrypted linked session |
| Upload official skin | POST `/api/v1/minecraft/official/skin` | linked session; multipart `file` (PNG), `variant` (`classic` or `slim`) |
| Reset official skin | DELETE `/api/v1/minecraft/official/skin` | linked session |
| Select owned official cape | PUT `/api/v1/minecraft/official/cape` | linked session; JSON `{"capeId":"<one of profile.capes[].id>"}` |
| Hide active cape | DELETE `/api/v1/minecraft/official/cape` | linked session |
| Start an official Minecraft game | POST `/api/v1/minecraft/official/launch-credentials` | linked session; read-only Minecraft identity verification |

After `start`, show the Microsoft-provided `userCode` and `verificationUri` to
the player. The user signs in directly at Microsoft. Submit the encrypted
`flow` as `X-Official-Minecraft-Session` when polling. Pending returns HTTP
202 with the **rotated** flow and the minimum polling interval; respect that
interval and `Retry-After`. On success, the API returns the authenticated
Microsoft-owned Minecraft profile and an opaque encrypted `session` ticket.

Supply that ticket in `X-Official-Minecraft-Session` for subsequent official
operations. If Minecraft token refresh occurs, replace the ticket with the
**new value in response header** `X-Official-Minecraft-Session`. Desktop's
`official_minecraft_0257.ts` handles that rotation and keeps the ticket only
in memory (not localStorage or the saved Tauri account config). The Never
access/refresh session remains in the existing OS credential store as before.

### Skin/cape semantics

- Official skins are uploaded **directly** to Minecraft Services using the
  access token for the authenticated Microsoft account. The PNG goes through
  the complete 0.25.2 parser/normalizer first; upload supports 64×64 (or
  64×32 classic legacy). Official Minecraft may enforce stricter limits;
  upstream validation errors are surfaced, never bypassed.
- Official cape activation enumerates the **authenticated** Minecraft profile's
  owned `capes[].id` and rejects any foreign ID. No custom project-granted
  cape can be added to that list. Reset/delete applies only to the active
  official skin/cape via official Minecraft Services.
- Official metadata/skin/cape URLs come from the real Minecraft profile.
  They are never copied into local-Yggdrasil assignments and Launcher
  **never signs** them with the local Yggdrasil key.

### Desktop identity selection and game launch

The **Авторизация** panel lets the player complete Microsoft device login,
inspect the verified official profile, upload/reset its skin, and select/hide
an owned cape. Account mode defaults to **local** and must be explicitly
changed to **official** before launch. `userType=msa`, the official UUID and
the real Minecraft bearer are passed to the native Runtime. No local
Yggdrasil URL or authlib-injector agent is injected for `msa`. Any signed
manifest JVM args containing authlib-injector cause this official mode to fail
closed. Official tokens may not be used for local ServerBridge join; this
version blocks official mode while a local `serverId` is selected, and it
rejects official mode for offline launches.

Reopening Desktop or logging out clears the official ticket and requires a
new Microsoft device-code login. A long-lived Microsoft refresh token is
kept only inside AES-256-GCM authenticated encrypted session tickets; tickets
are scoped to Never user and Never session ID and expire within 30 days. The
API does not save tokens or Microsoft profile IDs in the local texture or
Minecraft session tables. The API does not print or log the official bearer.
For rotation, replacing `LAUNCHER_AUTH_TOKEN_SECRET` invalidates all
outstanding official tickets.

### Testing and remaining release checks

Unit tests in `internal/officialminecraft` exercise Microsoft device grants,
Xbox/XSTS identity chain, Java profile, owned/unowned capes, multipart skin
upload/reset, refresh, redirects and response limits. Tests in
`httpapi/minecraft_official_0257_test.go` cover encrypted tickets, tampering,
expiry and polling throttling (run them with full API dependencies). Desktop's
`npm run test:official` exercises the actual TypeScript client. Before a
production release run a full Go/TypeScript/Rust build and e2e with a real
personal Minecraft Java account, licensed or accessible Game Pass profile,
real Microsoft app registration, authenticator, live texture selection and
actual client login. The supplied change archive is **not** a signed release
certificate and does not claim those live checks passed.

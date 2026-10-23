# NeverLauncher 0.26.1 — Own-app Microsoft → Xbox → Minecraft provider POC

## What is actually implemented

Run the **executable** Go CLI `services/api/cmd/official-provider-poc` against the
real Microsoft personal-account, Xbox Live, XSTS and Minecraft Services hosts.
It does not use Never's Microsoft/OIDC platform login and does not modify or
authenticate local/Yggdrasil profiles. This is an isolated engineering
preflight, not yet the native Desktop account manager planned for 0.26.2+.

The tool checks, in order:

1. Explicit UUID for **your own** registered Microsoft Entra public-client app.
2. Interactive personal Microsoft account login: **system browser + authorization
   code + PKCE S256** on local loopback, or optional `--flow=device` with compliant
   minimum polling, `slow_down`, expiry and cancellation.
3. Microsoft `offline_access` refresh (actually exchanges the refresh token).
4. Xbox Live user authentication (`RpsTicket: d=<Microsoft access token>`).
5. XSTS with `RETAIL` sandbox and `rp://api.minecraftservices.com/`, verifying
   matching user hashes.
6. Minecraft Services `/authentication/login_with_xbox` using XSTS credentials.
7. Minecraft `/entitlements/mcstore` using **Minecraft** access token.
8. Minecraft `/minecraft/profile` using **Minecraft** access token; validates
   official 32-hex Java UUID and non-empty name.

The entitlement **count is diagnostic**. Some Game Pass-enabled accounts have
zero regular purchase-entitlement items. A working official Java profile is
required; neither an Xbox login nor a Microsoft OAuth success is sufficient.

## External prerequisites (mandatory)

- Register a **new app you own** in Microsoft Entra: *personal Microsoft
  accounts*; desktop/mobile (public client), **not** a confidential web client.
  Use `/consumers` authority. No client secret is required.
- For browser mode register the native redirect
  `http://localhost/minecraft-poc/callback` (desktop loopback authorization,
  port chosen dynamically; Microsoft ignores the port for registered localhost
  redirect URIs). Supported scopes: `XboxLive.signin offline_access`.
- For device mode allow public client/device code in your app registration;
  the app **still needs** permission from Minecraft Services.
- Obtain the application's actual Minecraft Services permission through the
  provider's current approval/review process. Refer to
  <https://aka.ms/mce-reviewappid> and Minecraft support guidance; validate the
  process independently if the form or responsible team changes.
- Use an actual personal Microsoft account with usable Java Edition access
  (or supported Game Pass entitlement). Do not feed anyone your password.

**An application created successfully in Entra is not automatically approved
for Minecraft Services.** `403 Invalid app registration` from Minecraft
Services is an external-blocked state, not a reason to impersonate another
client ID or generate local official credentials.

## Run the live POC

From the repository root:

```sh
cd services/api
# Replace this UUID with your OWN Entra application client ID:
go run ./cmd/official-provider-poc \
  --client-id 'YOUR-OWN-APP-CLIENT-UUID' \
  --flow browser \
  --timeout 15m \
  --report ./official-minecraft-live-evidence.json
```

For environments unable to open a browser automatically, add `--no-open`
and open the printed Microsoft URL in the **same machine's** browser. For the
secondary device-code POC, use `--flow=device`. Use a NEW report filename on
every run; the command will not overwrite previous results. Exit code `0`
means the live sequence returned a valid Java profile; `2` means the provider
chain was blocked or failed; `3` means the evidence file could not be saved.

All Microsoft access/refresh, Xbox Live/XSTS and Minecraft access tokens remain
in process memory and are discarded at process exit; **none** are written to
report, environment, stdout or launcher storage. The *interactive terminal*
shows the ephemeral authorization URL or one-time device code (do not paste
this into a ticket); the JSON file contains only stage results, safe error
classifications, the explicit app UUID and SHA-256 of the Minecraft Java UUID,
**not** the username, email, authorization code or token. Evidence files use
exclusive creation and Unix `0600`; on Windows, protect the file with account
ACLs. Do not run with tracing/proxies that capture authorization headers.

Example successful **report structure** (illustrative only, NOT a real pass):

```json
{
  "schema": "neverlauncher.official-provider-poc.v1",
  "version": "0.26.1",
  "oauthFlow": "browser",
  "provider": "fixed_official_microsoft_xbox_minecraft_hosts",
  "stages": [{"name":"microsoft_oauth","status":"passed"}],
  "result": "provider_access_verified",
  "minecraftServicesAccess": "verified_live_profile",
  "externalAppApproval": "requires_independent_provider_confirmation"
}
```

A 403 with `invalid_app_registration` is classified in the report as
`minecraft_app_not_authorized` and `result: blocked`. Missing Xbox profiles,
family/child settings, region restrictions, revoked refresh credentials,
consent denial and provider unavailability are **not** converted to success.
No anonymous profile or fake Minecraft token is created.

## Release / external approval gate

The code and local unit tests alone **DO NOT complete MS01**. Before unblocking
subsequent rollout, record privately:

- Independently verify ownership of the exact Client ID and app registration type/scopes/loopback redirect (UUID format alone does not prove ownership).
- The real `--flow=browser` report with every stage actually passed.
- At least one actual `--flow=device` test of the same app (where permitted).
- Confirmation of Minecraft Services app registration/access from the
  responsible provider team, if applicable, with date/reference. API success
  proves technical access, **not a formal approval email**.
- Independent validation of gameplay on an `online-mode=true` server
  (including join/hasJoined) as a later **MS10 / 0.26.12–0.27.0 GA** gate.

Failure to obtain provider authorization is a **release blocker**. No CI stub,
mock, unit test, manifest, report copy, or manual switch substitutes for
successful live provider calls; an editable JSON report is not signed evidence.

## Automated tests (do not replace live sign-in)

```sh
cd services/api
go test -race ./internal/officialminecraft ./cmd/official-provider-poc
go vet ./internal/officialminecraft ./cmd/official-provider-poc
go build -o /tmp/neverlauncher-official-provider-poc ./cmd/official-provider-poc
```

The unit tests mock network responses to verify cryptographic/HTTP input
validation, status classification, callback state validation, report redaction,
and stage ordering. There is intentionally **no mock/live selector** in the
compiled CLI: production execution always targets fixed provider HTTPS hosts.

# Launcher 0.26.3 — Browser OAuth + PKCE (MS03 preparatory integration)

## Operator setup (required before enabling official login)

1. Register **your own** Microsoft Entra application supporting **personal Microsoft accounts**. Use a **Mobile and desktop** / public-client application (not SPA or confidential client). Register the exact native redirect **`http://localhost/minecraft-poc/callback`** as a desktop redirect. Azure ignores the ephemeral localhost port in redirect URI matching but **not** the path. Do not configure a client secret for this native flow.
2. Assign the application's UUID to the existing Backend `NEVERLAUNCHER_MINECRAFT_MICROSOFT_CLIENT_ID` setting (see deployment `.env.example` / Admin authentication settings for the current key). Provide a strong independently configured Backend auth token encryption secret, as required by the 0.25.7 backend.
3. Obtain **actual** Microsoft/Xbox/Minecraft Services permissions for that app. Microsoft OAuth success alone does not establish Minecraft application approval. Run the 0.26.1 `official-provider-poc` CLI with this same Client ID and a real Minecraft Java account; archive its redacted stage report outside the repository.
4. Run Backend 0.26.3 with Desktop 0.26.3. Sign into the existing Launcher platform identity first; then in Desktop open **Официальный Minecraft → Войти через браузер Microsoft (PKCE)**. The default external system browser opens automatically; after personal-account consent, the loopback callback displays completion and Desktop shows the verified Minecraft profile.
5. If a desktop cannot open the browser or loopback callback (e.g. endpoint security), choose **Device Code (резервный режим)**. Do not embed Microsoft auth into a webview or copy someone else's client ID.

## Implemented request path

- `GET /api/v1/minecraft/official/browser/config` — authenticated private native-client registration metadata only. Fails closed when configured client UUID or encrypted ticket secret is absent.
- `POST /api/v1/minecraft/official/browser/exchange` — authenticated Never platform identity, strict bounded JSON containing `code`, `verifier` and `redirectUri`. Backend enforces valid PKCE verifier and fixed loopback callback path, derives own Client ID **only** from server configuration, redeems code with Microsoft and checks Xbox/Minecraft chain + Minecraft Java profile. It returns the existing authenticated/identity-bound encrypted official session.
- Rust binds `127.0.0.1:0` (ephemeral OS port) **before** launching the browser, constructs the registered localhost redirect, generates a fresh random 256-bit OAuth state and 512-bit PKCE verifier, sends the S256 challenge, validates the return callback with an exact Host/path/state check and accepts only one matched response.
- Secret values exist in native Rust and trusted Backend process memory. Never appear in React/renderer requests, desktop command parameters, logs, localStorage, diagnostics, URL preview, or text shown in the callback browser page. The backend session ticket persists exclusively in OS keyring as in 0.26.2. Microsoft refresh/game access tokens are inside the backend-encrypted session ticket.
- Cancellation is explicit, stops accepting callbacks and prevents a late grant from being persisted; abandoned attempts expire in 5 minutes. OAuth errors are normalized to safe user-facing diagnostics.

**Trust boundary:** In this milestone the Backend — not the Desktop — performs Microsoft token exchange and token refresh (existing Backend flow). Version 0.26.5 may move that work if required by the future native-client architecture. Renderer isolation does not mean the Backend has no credentials.

## Mandatory local/CI verification

```bash
cd apps/desktop
npm ci
npm run test:official
npm run build
cd ../..
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_browser_0263::tests
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
cd services/api
go test ./internal/httpapi -run 'TestBrowserPKCE|TestOfficial' -count=1
# Real live approval/test (operator only):
go run ./cmd/official-provider-poc --client-id YOUR_REGISTERED_UUID --flow browser
```

Manual acceptance includes: valid account and official profile, refused consent, expired state, repeated and cross-origin callbacks, duplicate code/state, user cancellation before/during code exchange, simultaneous repeated login attempts, OS browser failure, native vault restore, and real Minecraft Services permission. Go and Rust simulated providers are **negative/regression testing only** and cannot certify real Minecraft permissions.

## Provider/error notes

- Microsoft `AADSTS50011` generally means the registered redirect **path/platform** does not match; use `http://localhost/minecraft-poc/callback` in the **mobile/desktop public client** configuration.
- A 403 `Invalid app registration` at Minecraft Services is a provider approval blocker, not something to work around with a different public Client ID.
- Only a Minecraft Java profile from Minecraft Services can set Official Ready. Microsoft/OIDC platform login alone cannot.
- If cancellation occurs after Microsoft issued a code, the backend may redeem it but the native manager refuses to commit its encrypted ticket after cancellation; the code cannot be reused.
- Backend and Desktop updates must be deployed together for this new flow; existing Device Code remains compatible with 0.26.2.

References: Microsoft Learn [redirect URI restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url), Microsoft Learn [authorization code PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow), [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252).

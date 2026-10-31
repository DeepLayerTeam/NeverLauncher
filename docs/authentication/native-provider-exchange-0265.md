# Launcher 0.26.5 — Native Microsoft → Xbox Live → XSTS → Minecraft

This release moves the **token exchange itself** from the Go Backend into the trusted Rust/Tauri Desktop process. It is a functional implementation; **external Minecraft Services approval and live game-server entry are not claimed**.

## Live authentication paths

1. **Browser (primary):** Native Tauri reads the Microsoft **public** Client ID from the authenticated Never Backend `/api/v1/minecraft/official/browser/config`. Tauri opens the system browser and validates the local PKCE callback (introduced in 0.26.3). The Rust provider submits the code+verifier directly to Microsoft's `consumers/oauth2/v2.0/token` endpoint with `XboxLive.signin offline_access`.
2. **Device Code (fallback):** Native Tauri obtains and polls Microsoft's `/devicecode` and `/token` endpoints directly. The native waiter enforces polling intervals, `authorization_pending`, `slow_down`, expiry and cancellation. `408`, `429`, `5xx` and transport errors use bounded retries. If Microsoft returned its one-time grant but Xbox/Minecraft is temporarily unavailable, the grant remains only in the native pending-flow memory for retries, rather than reusing the device code.
3. Both flows execute the same native **Xbox Live authenticate** (`RpsTicket=d=<Microsoft access token>`), **XSTS authorize** (Minecraft Services relying party), **Minecraft login_with_xbox** (`XBL3.0 x=<uhs>;<xsts>`), **entitlements/mcstore**, and **minecraft/profile** chain.
4. The trusted process verifies the Xbox user hash across both responses, Minecraft bearer/token type/lifetime, Java profile UUID and valid player name. A live Java profile is authoritative; an empty entitlement list alone is not proof of no Game Pass entitlement.
5. The native OS credential store holds the Microsoft refresh token, Minecraft bearer, Minecraft bearer expiry and immutable registered Client ID (`schema=2`). Neither bearer nor OAuth code/verifier is serialised through Tauri IPC; the renderer gets a profile or a Device Code **user** code only.
6. Before **status**, **texture modifications** or **launch**, Tauri revalidates the Never session/configuration. Expired Minecraft bearers are reacquired by refreshing Microsoft, then performing the entire Xbox/XSTS/Minecraft chain. Refresh-token rotation is saved before further provider calls. UUID changes after refresh are rejected.
7. Native official credentials flow only to Runtime for real game launch (`user_type=msa`, official UUID). Runtime's command preview continues to redact bearer tokens. No local offline/Yggdrasil session is promoted into official identity.

## Existing installations

OS keyring entries from 0.26.2–0.26.4 (`schema=1`, encrypted Backend ticket) remain readable and usable. New logins create **schema=2** records. Old accounts are not silently migrated to a different Microsoft identity; disconnect/reconnect produces a native record. The OS credential slot name stays unchanged so upgrading does not erase users' credentials.

## External gates and production verification

- Set `MINECRAFT_MICROSOFT_CLIENT_ID` (your **own** registered public client app UUID) on Never Backend. Register an appropriate native public-client loopback redirect and personal Microsoft account support. Backend `AuthTokenSecret` is no longer needed for **reading public client config**; legacy ticket endpoints still require it.
- Test an account owning Minecraft Java or with appropriate Game Pass eligibility. Confirm Xbox/XSTS, Minecraft Services acceptance of the registered Client ID, entitlements and Java profile.
- Test browser callback and Device Code on Windows/Linux/macOS with real OS credential stores. Test `slow_down`, denial, expired grant, family restrictions, App ID refusal, rotated refresh token, XSTS user hash mismatch, temporary HTTP 429/5xx, disconnect and revocation.
- On a real `online-mode=true` vanilla and modded Minecraft server, verify actual join/hasJoined before certifying the release. Having a Minecraft bearer/profile is not equivalent to proving game-server entry.
- CI `native-provider-exchange-0265.yml` runs native Rust tests and compilation on three operating systems. Local environments without `cargo` cannot substitute a passing native compilation result.

### Developer commands

```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_exchange_0265::tests -- --nocapture
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_identity_0262::tests
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
cd apps/desktop && npm ci && npm run test:official && npm run test:textures && npm run build
```

### Security and approval restrictions

Do not use someone else's registered Client ID to bypass Minecraft approval, print access/refresh tokens, or emit raw upstream HTTP response bodies into logs. Test fixtures are deterministic negative/transport checks only, never evidence of live provider approval.

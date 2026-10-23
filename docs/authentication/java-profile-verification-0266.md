# NeverLauncher 0.26.6 — Minecraft Java profile, entitlements and identity gate

## Runtime behavior (native Rust/Tauri)

The Minecraft token is never sufficient alone to mark an account game-ready. Every new native Microsoft/Xbox/XSTS/Minecraft grant is followed by **two real, authenticated HTTPS requests using the same Minecraft access token**:

1. `GET https://api.minecraftservices.com/entitlements/mcstore` — JSON `items` must be a well-formed array of named items. Recognized **Java** entitlements are `game_minecraft` and `product_minecraft`; Bedrock/Dungeons/other items are **not** treated as Java licenses. `product_game_pass_pc`/`game_pass_pc` is a possible Game Pass indicator, not definitive standalone proof of Java access.
2. `GET https://api.minecraftservices.com/minecraft/profile` — must succeed and contain a valid nonzero 32-character hexadecimal Java UUID and a valid 3–16-character Minecraft username. Explicit demo profiles are not accepted. An HTTP 404 is a **hard rejection** (`NoMinecraftJava`); malformed JSON, 401/403, provider failures and missing fields also fail closed.

Java player profiles are authoritative for **playability** when the entitlements list is empty (which can happen for Game Pass). The entitlement list alone NEVER qualifies an account, even if it contains a Java product. The nickname is UI metadata only; persistent account identity is the verified Minecraft UUID, not an email or mutable username.

### Every use of a stored account

Before status, textures, or launch, native code checks Never identity session and Client ID, refreshes expired Microsoft/Xbox/Minecraft credentials in the trusted process, and validates both `mcstore` and the live Java profile again. The returned UUID must match the previously stored UUID irrespective of letter case. A changed UUID **fails** and requires explicit account reconnect. Usernames may change without changing the identity. No fallback to cached profile, local session, project Yggdrasil, or offline credentials is allowed after validation failure.

Tokens stay in the Rust process / protected OS credential store and are never returned to React. The old `schema=1` Backend ticket is supported unchanged during transition; the new native `schema=2` account needs no vault migration. Microsoft OIDC for logging into Never is **not** equivalent to Minecraft Java readiness.

### What this does NOT prove

- Whether Microsoft/Xbox family/privacy settings allow **multiplayer** for a specific user. Explicit XSTS family/age responses are categorized as `XboxFamily`, including `XErr` represented as a number or string. An otherwise valid profile does not override multiplayer privacy restrictions. A real vanilla/modded online-mode server join and Mojang sessionserver validation remain required for certification.
- External registration/allowlisting of NeverLauncher's own Client ID at Minecraft Services, or a successful production login. Requires an approved app and actual Java/Game Pass account.
- Cancellation/refund/license changes after the last live check. A fresh check occurs on the next status/launch; no offline success is synthesized when services cannot be reached.

## Negative and positive fixture checks

- Java entitlement + 404 Java profile -> denied.
- Empty entitlements + valid token-authenticated Java profile (possible Game Pass) -> accepted.
- Bedrock-only entitlement + conflicting stored Java UUID -> denied.
- Demo Java profile or malformed entitlements -> denied.
- Xbox `XErr` family restrictions as string or integer -> categorized with static redacted error message.
- Name change with same UUID -> accepted; UUID change with same name -> denied.

HTTP fixtures validate client request order and bearer attachment. They are **not** proof of provider approval. The native CI gate runs on Windows, macOS and Linux; sign-off additionally requires real account and `online-mode=true` multiplayer testing.

## Verification commands

```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_verification_0266::tests
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_exchange_0265::tests
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
cd apps/desktop && npm ci && npm run test:official && npm run test:textures && npm run build
```

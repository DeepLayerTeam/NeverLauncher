# NeverLauncher 0.26.7 — Official Minecraft multi-account and session lifecycle

## Working behavior

- **Add** an official account with system browser PKCE or Device Code fallback. Existing accounts remain in the native OS vault; after provider profile verification the newly authenticated Minecraft UUID is selected. Re-authenticating the *same* Minecraft UUID rotates/replaces just that credential entry.
- **Select** from verified saved official UUIDs. Selection fetches a fresh Java profile and enforces the stored UUID before making the account active. If that step fails, the previous active selection is not changed.
- **Restore** on Desktop start: migrates an existing 0.26.2–0.26.6 single-account entry into the 0.26.7 directory; loads the selected account and revalidates its Never session / provider profile before marking the launcher official-ready.
- **Refresh** on user request: Microsoft refresh grant (including refresh token rotation) → Xbox Live → XSTS → Minecraft Services. The new refresh token is committed to native keyring before the downstream chain so a subsequent Xbox/Minecraft outage does not cause accidental loss of a rotated refresh token. Every successful result is bound to the same official Minecraft UUID.
- **Logout** removes only the selected account from the native credential store and selects the first remaining account, if any. A logout is **local**: Microsoft may retain its browser session and its issued grants; it does not claim to revoke provider-wide sessions.
- **Re-login** adds or replaces a UUID without destroying unrelated accounts. Credentials are never transmitted to the React renderer.
- **Launch and textures** always resolve the current selected account under a native vault lock; no cross-account credential or texture mixup when selection changes.

## Security boundary and format

Keyring service remains `NeverLauncher Official Minecraft 0.26.2` for compatible migration. Key identifiers are derived by SHA-256 from Backend origin and Never session identity. Account slots are `<scope>.account.<minecraft-uuid>`; the credential-free directory is `<scope>.directory.0267`. Each account uses the existing bounded OS-keyring chunked format, with random generation and SHA-256 integrity check. The metadata-only directory stores at most 16 lowercase 32-character Minecraft UUIDs and one active UUID. No plaintext JSON files, tokens in Tauri command results, or Browser localStorage.

The 0.26.7 native vault remains scoped to the authenticated Never **session**, matching 0.26.2–0.26.6. This safely prevents accidental cross-Never-session reuse, but it does not yet share the accounts across unrelated Never sessions; cross-session Never identity linking is planned in 0.26.8. It is not an account-cloud sync feature.

## Recovery and failure behavior

- A corrupted/missing keyring fragment or invalid account directory fails closed. It cannot promote a different UUID or silently switch to offline auth.
- Migration saves the account in its new account-specific secure slot, commits directory metadata, and only then deletes the original single-account slot. A process interruption before completion leaves the old slot available for retry.
- Refresh token invalidation and missing Minecraft entitlements/profile never produce a ready-to-launch state; the user must explicitly re-authenticate.
- A temporary provider outage does not destroy a saved account. The active account remains indexed, but launch is blocked until verification works.
- Switching selection, logging out, and game launch serialize on the native vault mutex. Backend/renderer never receive the Minecraft bearer.

## Release gate

Run `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_identity_0262::tests`, `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml`, and `npm ci && npm run test:official && npm run test:textures && npm run build` from `apps/desktop`. CI workflow `multi-account-lifecycle-0267.yml` runs these on Windows/Linux/macOS. Manual testing must cover two distinct real Microsoft accounts with Java access, switching, refreshing, OS vault persistence after restart, logging out one account, re-login same UUID, revoked refresh token, and an offline provider outage.

**Blocking external prerequisite:** No release can claim real Microsoft/Xbox/Minecraft end-to-end certification until the project's *own* registered Microsoft application has been permitted to use Minecraft Services and the real-provider cases pass. Mocked negative tests are not a substitute.

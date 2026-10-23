# NeverLauncher 0.26.2: native Official Identity Manager

## Operational functionality

The existing Backend-owned Microsoft Device Code → Xbox Live → XSTS → Minecraft flow is
used **without changing provider grants**. The Desktop webview no longer receives the
opaque backend tickets (which contain Microsoft refresh and Minecraft access tokens)
or the official Minecraft game access token. Tauri's `official_identity_*_0262` commands
implement the *actual HTTP calls* to the existing authenticated Backend API.

The backend still handles actual provider exchange and refresh at this milestone. Native
OAuth PKCE and direct MS/Xbox/Minecraft exchange are separate 0.26.3–0.26.5 milestones.
This release does not falsely claim that Microsoft/Minecraft provider approval has been
received. Run `official-provider-poc` from 0.26.1 using your own registered public client
and real personal Minecraft account before enabling official GA.

### Working behavior

1. User authenticates to NeverLauncher (unmodified existing platform login). Renderer
   passes its platform bearer token and Never session ID to the native manager, which
   makes Device Code and subsequent official HTTP requests.
2. `begin` returns only Microsoft user code, verification URI, expiry, interval.
   The backend encrypted flow is held temporarily in **native memory only**.
3. `poll` uses the native flow and minimum configured polling interval; successful
   completion verifies a 32-hex official Java UUID and persists the linked ticket to
   the OS credential manager under a digest of Backend origin and Never session ID.
4. The OS credential backend must work. `NoEntry` means no linked identity;
   unavailable/locked/corrupt store produces an **error**, never silent plaintext
   fallback. Windows Credential Manager, macOS Keychain and Linux Secret Service
   require a properly configured and unlocked user session.
5. `status` restores by fetching fresh profile from the authenticated Backend; it
   will not treat a stored encrypted ticket as proof of current Minecraft access.
   Restarting Desktop works **only if the original Never session remains active**;
   new Never sessions must re-link in this milestone.
6. Skin uploads, resets, owned cape selection and profile reads are performed from
   Rust. Session ticket rotation is persisted in the OS vault. Public profile metadata
   is the only data passed back to React. Upload is size-bounded (4 MiB).
7. Native `launch_minecraft` obtains a fresh Minecraft access token from the verified
   ticket and immediately passes it into NeverRuntime. Renderer-supplied `msa` tokens,
   official+local mixed identities, and official+offline launches are rejected.
8. `cancel` removes the native pending Device Code session; `disconnect` deletes
   the stored ticket (not a global Microsoft grant revocation).

### Production security boundaries

- Native HTTP: HTTPS only, loopback HTTP for development, origin-only Backend URL,
  redirects disabled, bounded JSON responses (256 KiB), bounded timeouts (45 s).
- Secret values must not enter renderer state, localStorage, preview APIs, browser
  network requests, diagnostic exports or logs.
- The Microsoft verification URI is a *public URL*; the code can be displayed but
  must not be copied into production telemetry.
- No keyring migration from the former renderer session is possible without exposing
  the ticket once; the user must connect the official account once in the new version.
- Minecraft tokens are still visible to the spawned Minecraft Java process, as
  required by the game's protocol. Protect OS process inspection and logs accordingly.
- Any prior Backend `/launch-credentials` route remains present for compatibility with
  older Desktop builds. Sunset/removal requires versioned Backend API deprecation and
  official client minimum-version enforcement; **do not claim cross-version isolation**.

### Verification commands

```sh
cd apps/desktop
npm ci && npm run test:textures && npm run build
cd ../..
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_identity_0262::tests
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Manual/native acceptance requires an unlocked OS keyring, real Never session, real
Microsoft/Xbox/Minecraft provider credentials, successful linking, refresh and launch.
No mock can substitute for these checks. External application approval is still a
release blocker, as documented in `official-provider-poc-0261.md`.

### Deferred intentionally to later releases

Native browser PKCE, direct provider exchange, multiple account slots, long-lived
sessions independent of Never session ID, global provider logout/revocation, and
independent online-mode multiplayer certification are **not** promised in 0.26.2.

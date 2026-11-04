# Launcher 0.26.4 — Device Code Fallback

## Operator behavior

The primary official Minecraft login remains **system-browser OAuth + PKCE**. When browser sign-in is blocked by the operating system, select **Device Code (резервный режим)**. The Desktop shows Microsoft's approved verification URL and user code. Open it on any browser, enter the code and approve with a personal Microsoft account that owns Minecraft Java. The native Identity Manager waits and verifies the Minecraft Services Java profile automatically. There is no manual **Проверить вход** button.

Press **Отменить вход** to end the active attempt. The manager invalidates its flow in memory and interrupts both scheduled sleeps and HTTP polling. Browser/UI code never receives `device_code`, refresh tokens, official game bearer credentials, or backend-encrypted session tickets. The user code and verification URL are intentionally displayable.

Expired, denied, or permanently invalid accounts return an error and **do not** become linked. A new attempt requires another explicit click; it is **not** automatically restarted on application startup or expiry (RFC 8628). An interrupted network connection, 429/408 or backend 5xx is retried automatically with bounded exponential backoff; `Retry-After` and `slow_down` adjust pacing. Backend `202` returns an encrypted flow continuation and provider-determined next interval which are stored only natively. After Microsoft has successfully redeemed the one-use Device Code, the Backend moves into a separate **redeemed** state: its Microsoft access/refresh credentials are sealed inside the existing AES-256-GCM ticket, which never enters React. A temporary Xbox/XSTS/Minecraft failure returns a rotated encrypted `202` continuation, so the next poll resumes the provider chain without trying to redeem the used device code again. On grant redemption near expiry, the Backend extends only this already-redeemed finishing window by up to five minutes; a still-pending original Device Code is never extended. The native waiter uses `expiresIn` from authenticated backend continuation to track this deadline.

## Security/implementation

- `official_identity_begin_0262`: creates the provider challenge; registers a native flow before the HTTP call so user cancellation during request preparation cannot resurrect it.
- `official_identity_wait_device_0264`: waits in Rust with `tokio::select!`, respecting both expiry and cancellation, calls the current native poll operation at permitted times and returns a verified `OfficialProfile` only.
- `official_identity_poll_0262`: a one-shot native operation retained for compatibility. A per-scope random nonce and in-flight guard discard old callbacks and prohibit concurrent poll requests. Temporary failures preserve the ticket and schedule the next safe attempt.
- `official_identity_cancel_0262`: wipes the pending flow and signals the Rust waiter; a replacement login starts a new nonce. Existing linked accounts are not implicitly deleted by cancelling a *new* challenge.
- Official OAuth access tokens remain on the trusted Backend inside the established encrypted ticket, persisted in the Desktop OS keyring per 0.26.2. For cross-instance deployments the pre-existing Backend in-memory poll throttle requires shared distributed rate enforcement before declaring full multi-instance HA support.

## Tests and release gates

```sh
cd apps/desktop
npm ci
npm run test:official
npm run build
cd ../..
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml official_identity_0262::tests
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
cd services/api
go test ./internal/officialminecraft ./internal/httpapi -run 'TestOfficial|TestBrowserPKCE'
```

Manual QA on Windows/Linux/macOS: start → approve, start → `authorization_pending` multiple cycles → approve, upstream `slow_down` → delayed next poll, 429 `Retry-After`, upstream timeout/502 → automatic retry, cancel before challenge returns, cancel during sleep, cancel during network request, replace flow with new one, deny, expire, lose Never session, invalid Minecraft entitlement, restore existing account and run official launch. Ensure renderer/network logs contain no official secrets. Test with a real approved Microsoft app, owned Minecraft Java account and `online-mode=true` vanilla/modded server before calling the provider integration certified.

Normative pacing: [RFC 8628 §3.5](https://www.rfc-editor.org/rfc/rfc8628#section-3.5) and [Microsoft Device Code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code).

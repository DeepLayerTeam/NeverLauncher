# AI Chat Workspace — 1.2.2

The Desktop AI chat uses the existing authenticated `/api/v1/ai/responses` (POST, SSE) and `/api/v1/ai/usage` (GET) endpoints. There are no new migrations, provider credentials in Desktop, or additional paid endpoints. Configure the Backend as described in [AI Backend Integration](ai-backend.md), including explicit allowed roles, pricing and budgets. Use HTTPS. Installed Desktop uses a native Tauri/reqwest transport and reads the current access credential from the OS keyring, verifies the expected local session and account, and forwards bounded raw SSE chunks over an IPC channel. No Tauri CORS exception or direct OpenAI credential is needed. The optional browser preview uses the regular authenticated HTTPS API and requires an explicitly allowed web origin. SSE reverse proxy buffering and retries must remain disabled.

## Using the workspace

1. Sign in normally, including SkiF4er ID. Complete the existing first-run trust checks. Select a project and profile (optional; without a project the general chat is available).
2. Open **AI-чат / AI chat**. Desktop loads personal usage and the configured model from the Backend. The send action stays disabled while access is unconfirmed or the reported budget is exhausted. Server-side authorization and budget checks remain authoritative at every request.
3. Create a conversation or open a previous one. Type a message, review the context and consent to sending. Enable project context only if needed. Context contains selected project/profile IDs and channel, and, if a loaded manifest matches the selection, Backend, account and pinned key, its release, Minecraft version, loader and Java major version. No file contents, file paths, server addresses, logs, session tokens or API credentials are gathered automatically.
4. Send. The chat shows text deltas as plain text, not executable HTML, then the confirmed cost and token counts. Stop cancels the current HTTP request. Leaving the workspace, changing project/profile/account/backend/session or logging out interrupts an active request. The Backend may still charge for interrupted requests; check the budget before explicitly resending.
5. The personal usage summary is refreshed after each generation attempt and can be refreshed manually. For 401/403, check the session/role; for 429 check the budget or request limits; for 503 check the AI Gateway configuration. The client never automatically retries a paid request. Partial/error replies are marked and excluded from future prompt history; restore a question to the composer to retry manually.

## History and privacy

History is local to the current WebView storage, scoped by canonical HTTPS Backend URL, canonical user ID, project ID and profile ID (not email or access token). It survives Desktop restarts and access-token rotation. It is not cloud-synced and is **not encrypted**; this is logical account separation, not OS-level protection from someone with access to the same device or its data. Sign out to hide the workspace; delete conversations or clear the current scope before using a shared computer. Deletion does not remove the Backend accounting ledger, provider-side records or device backups. There is no automatic export of chat content into diagnostics.

Limits: 20 conversations per scope, 40 question/answer pairs per conversation, 2 MiB serialized history per scope, 12 KiB UTF-8 question, 128 KiB streamed answer, and 16 KiB UTF-8 final prompt. Browser quota may be lower; if a write fails before generation no paid request is sent. If it fails afterward, the response remains visible in memory and the UI reports the storage error; delete old conversations to recover. Corrupt history can be cleared explicitly, never silently discarded. A pending record left by a crash is restored as interrupted, never replayed automatically.

Each request is stateless at the provider: only the current question, optional previewed metadata and up to 12 most recent completed turns that fit the byte limit are sent. Older turns stay in history. Turning off project context removes the explicit metadata from future prompts; prior messages may still discuss that project. The user can start a new conversation for a clean context. Model output is informational; it cannot invoke native commands, change files or execute tools.

## Verification

```
cd apps/desktop
npm ci --ignore-scripts
npm run test:ai-chat
npm run test:accessibility
npm run build
```

The client tests exercise the actual HTTP client against a loopback fixture (test adapter only, no paid requests), the same SSE parser fed by the native IPC protocol, fragmented UTF-8, cancellation before and after dispatch, terminal event handling, role/budget failures, prompt bounds, and history isolation/recovery. The CI matrix also builds the frontend and runs Rust tests for native job reservation and cancellation. For live acceptance, configure the Backend with a restricted key and low budget, build/run Tauri, sign in as an allowed user, send a question with and without project context, follow up in the same conversation, stop mid-stream, restart Desktop, change project/profile and sign in as another user. Verify usage, history isolation, explicit deletion, revoked/denied roles and exhausted budgets. Repeat on each supported WebView platform. Live provider and native acceptance are separate from the automated fixture tests.

## AI Diagnostics (1.2.3)

Локальный анализ ошибок и подготовка обезличенного запроса доступны из раздела диагностики и из AI-чата. См. [инструкцию](ai-diagnostics.md).

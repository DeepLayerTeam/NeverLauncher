# AI Backend Integration — 1.2.1

AI is an opt-in, text-only server-side OpenAI Responses API integration. Desktop or Admin clients call the Launcher API with the usual local Bearer access token (including sessions created through SkiF4er ID). The OpenAI project key never needs to leave the Backend. There is no proxy for arbitrary upstream URLs, models, tools, files, images, prior response IDs or arbitrary provider parameters. No chat UI is included in this Backend release.

## Enable on the Backend

1. Apply database migrations, including `0120_ai_gateway`, using the existing migration procedure. PostgreSQL is supported, including shared-database HA; the single-node Linux SQLite HTTP repository creates its AI tables in its existing WAL/FULL transaction store at startup. Memory repositories cannot enable paid AI.
2. Create a dedicated restricted OpenAI project API key, enable access to the selected text model and configure provider-side spend alerts/limits. Use a secret injection mechanism (not a tracked `.env`, client configuration or image layer). The upstream endpoint is fixed to `https://api.openai.com/v1/responses`.
3. Set the following environment variables on every API replica; all replicas sharing a database must have identical model, rates, ceilings, budgets and roles. Restart API processes. Production Compose forwards these settings; do not publish the resulting environment/config dump.

| Variable | Meaning |
| --- | --- |
| `LAUNCHER_AI_ENABLED` | `true` to enable; default `false` |
| `LAUNCHER_AI_OPENAI_API_KEY` | Required secret project API key |
| `LAUNCHER_AI_MODEL` | Required exact model ID supporting streaming Responses and `max_output_tokens` (prefer a pinned version) |
| `LAUNCHER_AI_ALLOWED_ROLES` | Required comma-separated global role IDs (e.g. `owner,admin`); no implicit administrator/player access or wildcard |
| `LAUNCHER_AI_INPUT_TOKEN_CEILING` | Required conservative upper bound on billable input tokens; use the selected model's full context bound for conservative reservation |
| `LAUNCHER_AI_MAX_OUTPUT_TOKENS` | Maximum generated tokens, including reasoning; default 1024 |
| `LAUNCHER_AI_INPUT_RATE_MICROUSD_PER_MILLION` | Required ceiling price of one million uncached input tokens, USD × 1,000,000 |
| `LAUNCHER_AI_OUTPUT_RATE_MICROUSD_PER_MILLION` | Required ceiling price of one million output tokens, same units |
| `LAUNCHER_AI_MONTHLY_BUDGET_MICROUSD` | Required global UTC calendar-month budget; $10 = `10000000` |
| `LAUNCHER_AI_USER_MONTHLY_BUDGET_MICROUSD` | Required per-account budget, no larger than global |
| `LAUNCHER_AI_USER_RPM` | Rolling 60-second per-account request cap; default 6 |
| `LAUNCHER_AI_MAX_CONCURRENT` | In-flight requests per API process, default 4 |

Prices are intentionally not hardcoded: check [OpenAI pricing](https://platform.openai.com/pricing/) for the selected model and region. E.g. $2 per million input tokens is `2000000` (illustrative, not a model price). Use a ceiling that covers the maximum applicable context tier; cached tokens are deliberately charged at the uncached rate. Provider project limits and invoices remain authoritative: the Launcher ledger is an estimate under the configured rates, not a guarantee about total OpenAI charges, taxes, other applications or provider billing changes. Requests that cross midnight are booked to their admission month. Never share the key with another workload. Do not use a model with additional non-token billing.

Missing or invalid enabled configuration prevents API startup. Missing accounting storage prevents startup or admission; there is no memory fallback. Network timeout is 90 seconds; the prompt limit is 16 KiB UTF-8 (or lower under configured ceiling). Provider retries are disabled; a timed-out or interrupted call may still incur provider charges.

## Client API

```sh
curl --no-buffer --fail-with-body \
  -H "Authorization: Bearer ${LAUNCHER_ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"prompt":"Explain Minecraft JVM memory settings"}' \
  https://launcher.example.com/api/v1/ai/responses
```

Successful admission starts an HTTP 200 `text/event-stream`. Data is JSON per event (SSE parser must support arbitrary TCP chunk boundaries; never render deltas as HTML). Example:

```text
event: start
data: {"requestId":"e145a8b70fa941d9a2a18100c388d9e1"}

event: delta
data: {"delta":"Minecraft"}

event: done
data: {"requestId":"e145a8b70fa941d9a2a18100c388d9e1","inputTokens":12,"outputTokens":4,"chargedMicroUsd":20,"state":"completed"}
```

`error` is terminal, including provider timeout, refusal to complete, interrupted stream or accounting failure. EOF without `done` is not success. The example costs are illustrative. Cancellation closes the client request, propagates to the provider connection and settles accounting independently of the cancelled request context. The frontend must not automatically replay a paid request. 401 = invalid/revoked local session; 403 = role not permitted; 429 = rate, concurrency or budget limit; 503 = disabled or unavailable. During generation the access token and current role are checked again before first delta and periodically on further deltas. Use an HTTPS reverse proxy with buffering and retries disabled for this POST (included Nginx configs do so).

- `GET /api/v1/ai/usage`: current user's monthly usage and budget; requires allowed role.
- `GET /api/v1/admin/ai/usage`: global monthly usage and budget; requires the existing global `users:manage` permission.

Both responses contain `model`, `month`, `budgetMicroUsd`, and `usage` with `requests`, `chargedMicroUsd`, `uncertainRequests`, `inputTokens`, `outputTokens`. No other user's identity or prompt is returned. HTTP response bodies never forward raw upstream error messages.

## Accounting and operations

Before calling OpenAI, a durable transaction locks the UTC month and checks global/user spend plus per-user rolling rate. It books the full configured worst-case token cost (`reserved`) before dispatch. Competing PostgreSQL replicas therefore cannot independently spend the same remaining budget. SQLite serializes the same checks and insert inside `BEGIN IMMEDIATE`. On terminal usage, the actual reported input and output tokens are recorded, and reservation is replaced by the conservative configured tariff charge. Missing final usage, crash or cancellation after dispatch retains the full reserved amount (`uncertain` or `reserved`); no automatic refund. `done` is sent only after settlement commits. An accounting failure does not trigger another provider call. The journal records account ID, model, timestamp, state, reservation and usage, not prompts, replies, tokens or secrets.

Review unresolved rows (`ai_requests` with state `reserved` or `uncertain`) against provider usage and reconcile outside the paid traffic window; do not blindly delete them. Keep backups of the accounting tables, including reservations. Database restore can roll back spend counters: online PostgreSQL database restore is rejected while the local AI gateway is enabled. For any DB restore or SQLite/PostgreSQL transfer, stop AI on **all** replicas, preserve/reconcile the ledger against provider billing and restore it before enabling. The generic domain transfer tools are not AI-ledger transfer tools. Do not re-enable paid traffic on a database with a reset current-month ledger. Restrict DB access and retain ledger records under the deployment's privacy policy. `store:false` requests no Responses object storage at OpenAI; it does not override the provider's abuse-monitoring/data-retention policy. Inform users that prompts are sent to OpenAI; avoid secrets or sensitive server logs.

## Verification

```sh
cd services/api
go test -race ./internal/aigateway
go test -race ./internal/repository ./internal/httpapi ./internal/dbmigrate -run 'TestAIGateway|TestEvaluateAppliedSealedCatalog' -count=1
```

Set `LAUNCHER_TEST_POSTGRES_DSN` to an isolated disposable PostgreSQL database for cross-replica tests (never production). CI tests a local HTTP provider fixture, stream parsing, cancellation, billing failure, SQL reservations, user isolation, SQLite restart, and auth admission without any paid requests. A real acceptance test requires a project key and a small configured budget: run the curl above, verify `done`, compare monthly usage before/after, verify disallowed role and revoked session fail, and confirm provider usage independently. This release does not imply that such live acceptance has been executed.

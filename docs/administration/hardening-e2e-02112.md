# Launcher 0.21.12 — Admin Hardening & E2E

## Implemented hardening

- Unified Operations `GET /operations/{id}/attempts` returns only the public attempt number, outcome, timestamps and error. Worker identities, lease fences, internal IDs and tokens stay server-side.
- ServerBridge Admin prevents a second browser submit before React renders its disabled button; a pending control request is persisted before network IO. A lost ACK can only be retried with the exact saved request and key. Successful submissions retain the command ID for monitoring after refresh. Pending command state is scoped to the Backend URL, authenticated session and project, then cleared on explicit logout.
- Unified Operations Admin persists the intent and idempotency key **before** execute. After a lost reply, an operator must recover with the same key or explicitly clear recovery after inspecting jobs/audit. A fresh random key is not generated implicitly.
- The Admin HTTP client does not automatically replay mutations. Network failure or broken 2xx JSON after mutation is reported as an *indeterminate outcome*, not success. HTTP reason codes remain distinguishable.
- Login controls have associated accessible labels, autocomplete attributes and semantic error/status announcements.
- Backend job list no longer emits internal SQL driver messages to clients on storage outage.

Protocol v3 packets, command ACK schema and cryptographic/runtime binding are **unchanged**.

## Locally runnable checks

```bash
cd apps/admin && npm ci && npm test && npm run build
cd ../..
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
cd services/api && go test -race -count=1 ./internal/httpapi ./internal/repository
```

The real PostgreSQL/ServerBridge integration requires **Docker and Go module availability**:

```bash
bash e2e/scripts/run-admin-hardening-02112-e2e.sh
```

The script creates a disposable PostgreSQL 16 container on a dynamically selected localhost port, applies migrations, and executes real pgx integration tests: competing concurrent config revisions through independent PostgreSQL connections, restore-as-new-revision, ServerBridge v3 command enqueue/lease/ACK/idempotency/transactional audit, distributed HA leasing, event streaming, durable scope fencing/restart. It also runs HTTP tests with real route middleware for cross-project RBAC, anonymous denial, concurrent stale revisions, and rollback idempotency. It **fails** if Docker is unavailable; it does not substitute memory tests for PostgreSQL tests.

A CI workflow at `.github/workflows/admin-hardening-02112.yml` gates Admin production build, Node test suite, Go race tests and this PostgreSQL/ServerBridge integration for matching pull requests.

## Real-browser certification with a deployed Backend

The optional Playwright browser probe is a **live integration test, not a mock server**. Run only against an isolated test instance with real project/account fixtures and live Admin service. Provide:

- `E2E_ADMIN_URL`: URL of the built Admin frontend
- `E2E_API_URL`: URL of the same instance's Backend
- `E2E_ADMIN_TOKEN`: privileged, valid access token for a test administrator with `release:prepare`
- `E2E_OPERATOR_TOKEN`: token for an operator restricted to the test project
- `E2E_PROJECT_ID`: writable test project with release workspace enabled
- `E2E_FOREIGN_PROJECT_ID`: another project to which operator has no access

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
python3 e2e/scripts/admin-hardening-02112-browser.py
```

The browser probe uses two independent tabs with the *real* Backend draft store to exercise conflict (one 200, one 409), reload/recovery, temporary offline state, cross-project API 403, hidden privileged actions, and accessible login labels. It creates and cleans up one release draft. A script failure must fail certification; missing environment values are errors, never "skipped and passed".

## Remaining production release gates

Do not mark 0.21.12 GA-ready unless `npm run build`, `go test -race`, PostgreSQL+ServerBridge tests and real-browser tests all complete successfully in a provisioned CI or staging environment. Existing E2E scenarios exercise server command persistence/ACK, **not** a physical Minecraft server join; physical runtime certification is a separate gate.

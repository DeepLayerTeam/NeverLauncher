# Launcher 0.21.10 — Everyday Lifecycle

Admin 0.21.10 connects existing backend actions to interactive workflows. It does not change ServerBridge v3 or weaken backend authorization.

## Jobs

- `/api/v1/operations/jobs?projectId=...&limit=25&offset=0&status=...` lists jobs for a project only after a fresh `project:read` authorization decision. A role with only global authentication cannot list other projects.
- Status and attempt history come from persisted durable jobs. The listing is capped to 100 records per request (offset at most 10,000); no worker lease token, raw payload, or idempotency key is returned.
- Cancel is offered only for `pending` jobs. Retry is offered only for `failed`, `dead`, or `revoked`, and requires backend authorization and MFA. Running and successful work cannot be repeated from this view.
- Job links persist as `#/job-monitor?job=<ID>`. A browser restart does not cancel a server job. Audit links search the correlation/job ID.

## Backup and restore

- `GET /api/v1/operations/backup/status` enumerates archives. `POST /api/v1/operations/backups` creates a real archive containing PostgreSQL and configured storage data.
- `GET /api/v1/operations/backups/{id}` inspects immutable archive metadata. `POST /api/v1/operations/backups/{id}/restore-dry-run` validates digest and restore input.
- Restore requires BOTH `storage:manage` and `settings:manage` in the UI, fresh phishing-resistant step-up on the server, a successful dry-run in the same UI flow, explicit component choices, exact typed backup ID, and confirmation. Backend creates a safety backup first.
- **Important**: the existing restore endpoint is synchronous, not a durable job. If the browser disconnects during restore, do not retry automatically. Inspect the audit and current storage/database state. If an error occurred after creating the safety archive, preserve its ID for recovery. The browser cannot guarantee atomic rollback across PostgreSQL and local storage.

## Sessions and devices

- Every authenticated user can see and rename/revoke their **own** sessions. Revoking the current session signs out of Admin.
- Users with `users:manage` additionally see trusted device records. Device revocation is irreversible, requires a nonempty reason, explicit confirmation and the backend phishing-resistant step-up. The backend invalidates associated sessions and challenges; the UI reports counts from the actual response.
- Read permissions are checked by the Backend on every request. UI action hiding is not a security boundary.

## Extensions

- Registry signing, installation, host lifecycle, enable/disable, update, rollback and uninstall use existing real backend routes.
- Mutating actions show the exact extension/version/scope and require confirmation. Operation responses are retained in the UI, while the refreshed manager reflects current state. Errors explain reauthentication/permissions/reload and link to audit; never infer that a transport error means no side effect.
- Existing sandboxed extension UI and RPC permission controls remain unchanged.

## Test requirements for production sign-off

Run the complete Go suite with dependencies installed, `npm ci && npm run build` in `apps/admin`, then authenticated browser E2E connected to PostgreSQL. Exercise non-owner authorization denial for cross-project job listing; archive dry-run failure; step-up expiry; lost HTTP response during backup restore; session revocation; extension update rollback, and repeated/cancelled durable jobs.

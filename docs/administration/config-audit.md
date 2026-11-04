# 0.21.11 Config & Audit — operational usage

## Online configuration

`Admin → Конфигурация` is available only to global `settings:manage`. The editor
contains **six explicitly whitelisted, non-secret settings** (audit and jobs API
pagination, default audit query lookback and audit search client detail exposure).
These values are read from the shared PostgreSQL store on each request, so all API
replicas observe the latest committed revision without a process restart. No
application secret, auth configuration, signing key, CORS, network, storage or
database connection parameter is editable in Admin.

Each `PUT /api/v1/admin/config` requires live authorization, recent MFA,
`expectedRevision`, full typed `settings`, and human-readable `reason`. Use
`POST /api/v1/admin/config/validate` before applying. The server computes the
diff and validates bounds. The actual update is guarded by PostgreSQL CAS; a
409 `revision_conflict` indicates that a different session already committed a
new revision. Refresh, review the diff, and validate again. Do not silently
retry a stale update. Restore via `POST /api/v1/admin/config/restore` with the
target `restoreRevision`; it creates a new revision instead of deleting history.
The UI requires a matching textual confirmation and MFA for applying/restoring.

Database migration: `0055_config_audit_02111.sql` seeds revision 1 and indexes
audit correlations. Deployment must apply migrations before sending traffic.
The history API returns the latest 50 revisions; restoring a target more than
100 revisions old requires operational handling rather than bypassing the CAS.

## Audit search

`GET /api/v1/admin/audit` requires global `audit:read`. Backend filtering includes
`search`, `actor`, `action`, `target`, `correlationId`, `reasonCode`, `jobId`,
`from`, `to`, `limit` and `offset`; result includes `items`, `total`, `limit`, and
`offset`. Without `from`, `auditLookbackDays` determines the default range.
`limit` is bounded by `auditMaxPageSize` and `offset` by 100000. The search
queries the PostgreSQL audit table, not an in-browser copy of its most recent
500 entries. Correlation IDs are server-generated (`X-Correlation-ID` response
header), not accepted as arbitrary caller authority. Authorization failures
made by global and project middleware emit `authorization:denied` audit entries
with `insufficient_permissions` reason. Events with a known job ID link to the
Job Monitor. Existing events predating this migration do not gain retroactive
correlation/reason metadata.

Audit records do not establish exactly-once status for synchronous destructive
operations. Inspect the target service's own state and job details before
retrying. Export/other legacy audit consumers are separate interfaces.

## Caveats

Go integration and full production Admin builds must be exercised in an
environment with the pinned Go and npm dependencies plus PostgreSQL. Do not
interpret static checks as production certification.

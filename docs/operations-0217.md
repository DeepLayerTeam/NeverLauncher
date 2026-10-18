# NeverLauncher 0.21.7 — Unified Operations

This is an executable backend workflow, not a manifest-only registry. Registered kinds:
`package-publish`, `channel-rollback`. The existing `/api/v1/packages/{packageId}/publish`
and `/api/v1/channels/{channel}/rollback` entrypoints remain supported.

All endpoints require a valid Admin Bearer session. `execute`, `cancel` and `retry`
require fresh MFA according to the configured step-up policy and `release:publish`
permission in the *actual project*. The backend checks permissions again when a
worker starts and before mutating files or committing a published release.

## Endpoints

| Action | Method | Path |
| --- | --- | --- |
| Registry | GET | `/api/v1/operations` |
| Preview / validate | POST | `/api/v1/operations/validate` |
| Execute / enqueue | POST | `/api/v1/operations/execute` |
| Status | GET | `/api/v1/operations/{operationId}` |
| Attempt journal | GET | `/api/v1/operations/{operationId}/attempts` |
| Cancel pending | POST | `/api/v1/operations/{operationId}/cancel` |
| Retry failed/revoked/dead | POST | `/api/v1/operations/{operationId}/retry` |

### Request examples

```json
{"kind":"package-publish","projectId":"example","resourceId":"example-vanilla-1.0","idempotencyKey":"release-example-1.0"}
```

```json
{"kind":"channel-rollback","projectId":"example","profileId":"vanilla","channel":"stable","toVersion":"1.0","idempotencyKey":"rollback-stable-to-1.0-20261018"}
```

`validate` is read-only and displays the concrete effect; `execute` queues a durable
job, returns HTTP 202 and a `Location` pointing to the operation. The legacy
rollback endpoint performs an immediate opportunistic execution for compatible
clients. If the worker remains busy it responds with HTTP 202 and the job ID.

An explicit `Idempotency-Key` header takes precedence over the JSON field. Clients
must **retain the same key across network retries** and use a different key for
an intentional new rollback. Reusing the same key with a different resource,
project, profile or target version returns HTTP 409. If omitted, a deterministic
key is derived from the actor and frozen request payload; this deliberately
prevents accidentally performing an identical rollback a second time.

The operation ID is the `X-Correlation-ID` and identifies one durable job and
all of its attempts. PostgreSQL stores attempts in `durable_job_attempts`; jobs
and idempotency records live in the existing 0.21.3 durable tables. No new
schema migration is required. The CLI uses the same endpoints:

```bash
nl adminops operation registry --backend https://api.example.org --token "$TOKEN"
nl adminops operation validate --backend https://api.example.org --token "$TOKEN" --kind channel-rollback --project example --profile vanilla --channel stable --to-version 1.0
nl adminops operation execute --backend https://api.example.org --token "$TOKEN" --kind channel-rollback --project example --profile vanilla --channel stable --to-version 1.0 --key rollback-20261018-1
nl adminops operation status --backend https://api.example.org --token "$TOKEN" --id job_ID
nl adminops operation attempts --backend https://api.example.org --token "$TOKEN" --id job_ID
nl adminops operation cancel --backend https://api.example.org --token "$TOKEN" --id job_ID
nl adminops operation retry --backend https://api.example.org --token "$TOKEN" --id job_ID
```

## Execution guarantees and constraints

- Only `pending` jobs are cancellable. An already `running` or `succeeded`
  job is never reported as safely cancelled.
- Retrying a terminal job preserves its ID, idempotency identity and entire
  attempt journal. Old lease tokens cannot complete a later attempt.
- `channel-rollback` materializes **one deterministic release per operation**.
  It checks source manifest signature and source-file digests, copies missing
  objects on recovery, generates a new signed immutable manifest, runs an
  integrity check, and publishes through the existing `CommitDurablePublish`
  transaction and outbox. A required runtime validation instead leaves a
  staged, integrity-checked release for a subsequent explicit publish.
- Job leases use PostgreSQL `FOR UPDATE SKIP LOCKED` and retry after crashes.
  The request-side opportunistic execution is disconnected from HTTP client
  cancellation to avoid orphaning jobs when browsers disconnect.
- Runtime validation is never forged. An integrity check does **not** prove a
  Minecraft client launched or joined a server.
- PostgreSQL remains the mandatory production repository for multi-instance
  operation recovery. The memory repository is for deterministic unit tests.

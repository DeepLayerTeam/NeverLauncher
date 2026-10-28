# NeverLauncher 0.34.12 — Validation Reports & Security Hardening (V12)

## Deployment order

1. Back up the database and apply API migrations through the existing migration runner, including `0106_validation_audit_03412.sql`. The migration installs an append-only event table and **AFTER INSERT** triggers on the existing staged-execution and attestation tables. A failed trigger insert rolls back the corresponding evidence write. Events generated before migration remain available through the existing stage/attestation records, but earlier rejected requests cannot be reconstructed retroactively.
2. Deploy API 0.34.12 and Admin 0.34.12 together. V12 application handlers reject attestation/staged submissions when the new audit writer is unavailable. Keep 0.34.11 PostgreSQL stable-head guards and trusted keys configured. **Do not remove or disable V11**.
3. Run the independently hosted attestor with `--diagnostics-dir /secure/validation-diagnostics --diagnostics-ttl-hours 168`. Directory must be 0700, owned by the unprivileged attestor account and on encrypted persistent storage. The option is required; an unavailable directory fails closed before the evidence is returned. Only sanitized logs (maximum 2 MiB/run), a SHA-256 digest and an expiry are retained; raw worker stdout is ephemeral. New jobs prune expired records. Run an external scheduled cleanup so expiration is enforced even when no jobs arrive.
4. Restrict write access to `validation_attempt_events_03412`, `package_validation_attestations_0345`, `stable_runtime_permits_03411` and migration/trigger functions to dedicated backend roles. The audit table rejects UPDATE/DELETE; backups/WAL should be retained per operational policy. A PostgreSQL owner/superuser able to alter triggers is outside this application-layer threat model; monitor such actions via PostgreSQL server audit logs. Rejected SQL statements roll back, so they do not automatically generate a durable row in the same transaction.

## Auditing and privacy

`GET /api/v1/packages/{packageId}/validation-report` requires `project:read`, returns an immutable event page (100 latest rows, `nextBefore` for cursor pagination), latest staged runs with stage hashes, signed evidence summaries (without signed payloads), validity/expiry and the live V11 target coverage/blockers. `?runId=<runId>` fetches an **exact historical** run and its attestation beyond bounded list windows. Reports are `Cache-Control: no-store`. Stage detail is sanitized both on ingestion and when old rows are read. Backend never trusts a diagnostic string or audit event as a certification decision.

Validation audit event rows contain only package/run IDs, outcome, bounded reason code, SHA-256 of submitted/observed data and creation timestamp. Accepted staged reports and accepted attestations are journaled transactionally in PostgreSQL. Malformed, forged and stale submissions are journaled as `rejected`; pre-commit failures of V11 are journaled as `blocked`. Audit failures prevent the application from issuing a stable permit. A `stable-gate/eligible` event is **not proof of commit**; check Durable Publish and the actual channel head for final publish state.

Tokens, passwords, OAuth secrets, sensitive Java arguments, bearer headers, account/email identifiers and UUIDs are redacted by default with no HTTP override. Do not put secrets in file paths, release IDs, version strings or manifest metadata: these are immutable identity fields rather than diagnostics. Signed evidence itself contains hashes and public metadata; its signature must not be rewritten for redaction.

## Adversarial verification

- Forge the Ed25519 signature or use an unrelated signer: `rejected/untrusted-signature`; stable does not change.
- Present a stale, revoked, replayed or cross-target evidence: record the reject reason; runtime coverage remains incomplete.
- Submit `{"certified":true}` or an unknown field: decoder rejects it; no handler ever sets a manually asserted certification flag.
- Modify local Java/JAR, screenshots, player ticks or evidence hashes in a compromised worker: independent attestor must reject the run. Compromising the **attestation host itself** is a distinct security failure and must be mitigated operationally by access control, host attestation, trusted image digests and key rotation.
- Race key revocation, evidence expiry, release mutation and stable channel changes: existing V11 SQL guard must deny without a valid one-use permit and matching signed target matrix. Do not equate an `eligible` audit event with a committed release.
- Attempt `UPDATE` or `DELETE` of audit rows: triggers reject both. Confirm keyset pagination and historic `runId` lookup after more than 100 attempts.

## Testing commands

`python -m unittest discover -s tools/validation-attestor -p 'test_*.py'`

`cd services/api && go test ./internal/httpapi ./internal/repository ./internal/model`

`NEVERLAUNCHER_TEST_POSTGRES_DSN=<disposable-db> go test ./internal/repository -run 'TestV12|TestV11'`

`cd apps/admin && npm ci && npm run build`

**GA/production acceptance requires** a disposable PostgreSQL instance, the project-required Go toolchain, a real attestor and signed Minecraft client/server staged artifacts. Unit tests or schema checks alone do not establish production security or real client/server compatibility.

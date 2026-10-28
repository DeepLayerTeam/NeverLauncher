# NeverLauncher 0.33.13 — MIG13 Reports & Certification RC

## Purpose

The `report` command and Admin Migration Center render an **actual database-derived** inventory of transferred, transformed, manual and blocked objects, source and target UUID mapping, SHA-256 evidence, and the chronological sequence of operator/migration events. No caller uploads or assembles the report. The report is regenerated using a read-only **REPEATABLE READ** PostgreSQL transaction against MIG02–MIG12 receipts and the current Never build workspace/channel head state.

Every generated report has `reportSha256` over its canonical JSON representation excluding only that digest field. Arrays are ordered deterministically; the SHA-256 changes if evidence, file mappings, identities, route state or migration events change. The self-referential `gravit_report_rc_reviewed` audit event is excluded to avoid invalidating the review solely by recording it.

A report may have status:

- `blocked`: missing evidence, invalid or unsupported migration components, unresolved UUID mappings or unsafe/stale target state.
- `review_required`: the recorded inputs passed the implemented checks, **but** operator/independent real-server tests, source fencing, player transition, platform support and release certification must still be verified. It is **not** a GA or automatic cutover authorization.

The `operatorDecisions` array preserves migration event sequence, kind and revision, omitting event details that could accidentally contain secrets. Items include source→target path, reason and checksum where available. Full historical CLI/CI log files and third-party JAR binaries are not embedded.

## CLI

```bash
nl migrate gravit report --backend https://example.invalid --token <ADMIN_TOKEN> --run <ID> --output ./migration-report.json
nl migrate gravit report-review-status --backend https://example.invalid --token <ADMIN_TOKEN> --run <ID> --output ./reviewed.json
nl migrate gravit report-review --backend https://example.invalid --token <ADMIN_TOKEN> --run <ID> --confirm <ID> \
  --report-sha256 <SHA256_FROM_FRESH_REPORT> \
  --evidence-sha256 <SHA256_OF_INDEPENDENT_TEST_RECORD> \
  --evidence-reference <IMMUTABLE_CI_OR_TEST_RECORD_REFERENCE> --output ./reviewed.json
```

Admin uses the same endpoints: `GET /api/v1/admin/migration-runs/{runId}/report`, `GET .../report/review`, and `POST .../report/review`. Access requires `settings:manage` for the specific project, and review additionally requires fresh MFA and `X-Migration-RC-Confirm` equal to the run ID. The final review is immutable in PostgreSQL and protected by a DB trigger. A review is replay-safe with the original digest, identity and evidence reference. If new migration evidence appears after a review, the old review remains an historical immutable snapshot; it is not silently updated.

**Never send raw ZIP archives, password hashes, OAuth tokens, session keys, Guard evidence or device private keys in a report.** The report is itself restricted: UUIDs, usernames, content paths and business inventory can be sensitive. Distribute it only to authorized operators. Source exports from MIG03 may contain secrets and should be stored separately with restrictive access controls.

## Certification / exit matrix

- [ ] Backend Go 1.27.3 full build, unit and race tests, including PostgreSQL 17 integration.
- [ ] CLI test and full build. OpenAPI route-contract validation and version-metadata consistency.
- [ ] React Admin production build and Embedded Admin JavaScript checks.
- [ ] Exact Gravit 5.7.x fixtures with independently verified version/build provenance and explicit compatibility per patch version.
- [ ] Actual isolated Minecraft launch, login, join, skins, Forge/NeoForge, optional mods and administrative rights, with real world/plugin UUID/inventory/permission/economy snapshot comparison.
- [ ] Player migration clean install and cache adoption on the declared supported OS/architectures and official signed installer distribution.
- [ ] Controlled canary cutover where source writers are independently fenced and Never channel traffic is observed; a dedicated rollback drill with data reconciliation where necessary.
- [ ] No unsupported auth provider, ambiguous UUID, unknown auth/launch module or missing checkpoint is treated as fully compatible.
- [ ] External test artifacts are archived, immutable and SHA-256 pinned to the source commit/target release. An operator reviews the *actual* stored results, then records the RC review.

The CI workflow `.github/workflows/gravit-migration-reports-03313.yml` runs the available API/DB, CLI, Admin, version and OpenAPI gates. **It does not manufacture or prove a live Gravit/Minecraft E2E.** No migration report automatically declares `fully_compatible` or `production_certified`. Missing evidence must be reported, not silently accepted. Production GA remains the separately reviewed 0.34.0 exit process.

## Recovery / failure behavior

Generating the report is side-effect free. A failure or concurrent migration yields a retryable error, not a fabricated successful report. Review uses a serializable transaction and locks the run, compares the exact checksum to the current DB state, writes an immutable review and a sanitized audit event atomically. On uncertain HTTP completion, query `GET .../report/review` before retrying with the *same* body. Review never changes Minecraft worlds, accounts, release routing, external Gravit or trust anchors.

# Launcher 0.34.11 — Production Runtime Gate (V11)

## Publication prerequisites

The release must be staged with a valid release signature, current integrity PASS, a configured **complete** `LAUNCHER_VALIDATION_REQUIRED_TARGETS_JSON` matrix, and one live trusted v4 attestation for each required target. Each attestation must cover all nine required V02/V03/V07/V08/V09 stages. The trusted Ed25519 validation key and pinned OCI runner image must be configured. CI reports, legacy v1 validations, or an admin flag are not accepted as runtime certification.

The Admin Release Workspace displays the effective `trusted-runtime` policy, required/verified counts, target-by-target blockers, and whether the current package is eligible. The existing `/api/v1/packages/{packageId}/validations` response contains this information. An unavailable database, revoked key, changed package, missing target, failed/inconclusive stage, or expired evidence blocks stable.

## Durable publish

The API verifies authorization, signed manifest, current integrity and the **entire** required target matrix. Immediately before `CommitDurablePublish`, it re-evaluates the evidence and issues a random 256-bit, one-use permit (five minutes). The permit contains no assertion of `certified=true`; it references existing signed evidence rows for every required target. Inside the same PostgreSQL transaction the stable release status trigger and stable head trigger check the permit, current integrity, exact target fields, stored run challenges, expiration, and revocations. The head trigger consumes the permit atomically. No token is persisted in a durable job; on restart or retry it must be reissued after fresh evaluation.

Direct SQL status changes, direct repository publish, SQL head manipulation, cutover or rollback without a valid permit remain fail-closed. Dev and test channels retain their independent policy. Migration Center activation and rollback obtain the same fresh permit for their target release; deletion of the stable head is prohibited. Rollback-as-new-package is staged for separate runtime validation before it can be published.

`0105_production_runtime_gate_03411.sql` replaces the previous unconditional guard functions in place, preserving previously published stable releases. Do **not** disable the existing trigger names. Apply migrations with the repository migration runner. Evidence/challenge/revocation rows are append-only after migration. Grant insertion must remain limited to the backend's validated issuer path; restrict direct write access to validation tables and PostgreSQL administrative privileges. A DB superuser can change security functions, and is outside the API threat boundary.

## Required verification before enabling production

Run API and repository Go tests with the declared toolchain and a disposable PostgreSQL instance. Run `TestV11StableSQLRejectsForgedPermitAndManualWrites03411` and the prior `TestStableSQLTriggersRejectAllHeadAndManualStatusWrites0341`. Exercise positive staging, full multi-target trusted E2E and its real stable publication; repeat with one missing/failed/inconclusive target, expired/revoked evidence, changed preset/Java/plugin, concurrent publish and revocation, restart/retry, manual SQL writes, Migration Center cutover/rollback and rollback as a newly staged package. Only then can the rollout be called production-verified.

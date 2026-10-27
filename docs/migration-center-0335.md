# NeverLauncher 0.33.5 — MIG05 Authentication Migration

Operational auth migration from **the same ZIP** pinned by MIG03 Source Inventory and MIG04 Identity Mapping. Requires PostgreSQL durable mode and a globally authorized `settings:manage` administrator. Does **not** enable cutover, copy Gravit sessions, create administrative privileges, or trust legacy devices.

## Supported credentials

- FileAuthSystem: the real UUID-keyed `.../FileAuthSystem/Database.json`; the operator must select the original password hash algorithm after inspecting their deployment configuration. Supported: `sha256-hex`, `sha256-base64url`, `md5-hex`, `sha1-hex`, `sha512-hex`, `double-sha256-hex`, `double-sha256-binary-hex`, `phpass`, `bcrypt`, `argon2id`. Hash formatting and cost bounds are checked using NeverLauncher 0.29.5's production credential verifier. A wrong but syntactically valid operator choice cannot be detected cryptographically without testing a known account/password pair.
- SQL: operator exports actual SQL users to `sql-export/users.csv` in the pinned ZIP. Required identity columns: `id,username,uuid`. For password preservation add `password_hash,password_format` with explicit per-record format, e.g. `7,PlayerOne,11111111-2222-4333-8444-555555555555,<digest>,sha256-hex`. This normalized CSV is a snapshot, **not a database-connection URI**. Unknown/absent SQL verifier formats become per-account `manual_reset` rather than a mass reset or a guessed algorithm. The raw unknown hash is not stored.
- Official/remote/external/custom Gravit auth providers are **not** converted into local passwords by this release; use the appropriate supported provider through the existing authentication subsystem, and do not declare migration fully compatible. No old active session, OAuth credential, device key, Guard attestation, ServerWrapper key, trust anchor or user permission is imported.

## Runbook

1. Verify Never target with `nl migrate gravit execute ...`; pin source with `inventory` and map with `map-identities`. All commands use `--backend https://HOST --token TOKEN --run RUN` as applicable. Protect the token from process-list disclosure using `NEVERLAUNCHER_TOKEN`.
2. For FileAuth: `nl migrate gravit preview-credentials --backend https://HOST --run RUN --source /private/gravit.zip --fileauth-format sha256-hex`.
3. Review all `imported` (planned), `existing_unchanged` and `manual_reset` entries. Address blocked UUID maps first. If user passwords are in a nonstandard format, use an independently reviewed transition verifier or perform a targeted password reset; never guess or silently replace the hash.
4. After an explicit operator decision, run `nl migrate gravit import-credentials --backend https://HOST --run RUN --source /private/gravit.zip --fileauth-format sha256-hex`. The backend requires a matching `X-Migration-Import-Confirm` header, which the CLI supplies.
5. Reconcile the UUID map again with `nl migrate gravit verify-identities --backend https://HOST --run RUN`; created accounts should now match their original UUID. Then `nl migrate gravit credentials --backend https://HOST --run RUN` reads the durable sanitized receipt. Report files created via `--output` use exclusive mode `0600` and cannot overwrite an existing file.
6. **Manually test a real migrated account in a protected test environment**, including login, password upgrade to Argon2id, game UUID, world/plugin data and revocation of old sessions. This release alone does not authorize publishing or cutover.

## Transaction and security invariants

- Requests stage a bounded source ZIP, recheck both SHA-256 and the full inventory, and re-extract the *same* identity records. The API never accepts a client-provided password hash array or arbitrary user IDs.
- Import uses a PostgreSQL SERIALIZABLE transaction, a shared importer advisory lock, the locked migration run, and a previously approved UUID mapping. Changing UUID ownership after mapping blocks the transaction. Unique database constraints catch races with other writers.
- New accounts receive `player` and no project RBAC roles, with stable IDs and the original Minecraft UUID. Never identity matches are **never** password-overwritten or merged. Previously missing SQL password verifiers are left unimported for a targeted follow-up.
- The imported hash is stored only in `users.password_hash`. Existing login verifier upgrades it to Argon2id after the first successful password proof using compare-and-swap. No source passwords, legacy sessions, email tokens or hashes are put into reports, migration events, journals or HTTP output.
- Receipt and account writes commit together; network retry with identical source and format reads back verified created users, not duplicate inserts. The operator must recheck a possibly uncertain commit by `credentials` before changing source or credentials.
- Requires HTTPS except explicit loopback IP from CLI. Source ZIP and local reports remain sensitive; use encrypted storage, short retention, and strict filesystem access.

## Limits and non-goals

- MIG05 does not implement official auth migration, automatic SQL access, arbitrary custom verifier execution, unknown module loading, player installer, release signing, rehearsals, staged cutover or rollback; those are separate roadmap stages.
- Source ZIP limits follow MIG03: 512 MiB compressed, 2 GiB expanded, 30,000 entries. FileAuth's existing parser supports up to 16 MiB and 20,000 accounts per FileAuth JSON.
- Complete Go 1.27.3 + PostgreSQL 17 integration tests and React Admin production build must pass CI before a production-validated claim. No successful production deployment is implied by code presence.

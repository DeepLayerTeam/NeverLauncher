# NeverLauncher 0.47.4 — Offline Core state import and storage copy

This upgrade extends the existing **offline** verified SQLite Core 327 staging
import (`sqlite-to-postgres` + `sqlite-to-postgres-live`). It does not modify
historical PostgreSQL or SQLite SQL migration files. **Do not cut over the live
application on the strength of an import receipt alone.** Source and target
must be stopped; the target must be a new, fully migrated PostgreSQL database.

## Runbook

1. Stop API, coordinator, launchers/bridges, queue consumers, schedulers and any
   other writers. Make independently restorable offline backups of
   `http.sqlite`, `coordinator.sqlite`, the SQLite Core DB, storage objects,
   configuration files and encryption keys. Confirm the backups can be read.
2. Apply every shipped PostgreSQL migration to a **new, empty** database. Set
   `LAUNCHER_POSTGRES_DSN` in the operator's environment.
3. Import the immutable SQLite Core backup into cryptographically verified
   staging with `launcher-sqlite sqlite-to-postgres --backup <core-backup>`;
   see the preceding 0.47.3 runbook for staging flags and backup requirements.
4. Rewrap TOTP with the same private Core MFA key used on the source and the
   same secret as the destination HTTP API. Do not supply either secret as a
   command-line argument. Example:

   ```sh
   export LAUNCHER_POSTGRES_DSN='postgres://...'
   export NEVERLAUNCHER_PG_API_SECRET='the-exact-HTTP-API-secret'
   launcher-sqlite sqlite-to-postgres-live --from-staging \
     --sqlite-mfa-key-file /path/to/private/core-mfa.key \
     --postgres-secret-env NEVERLAUNCHER_PG_API_SECRET \
     --ack-live-import
   ```

   The key file must contain precisely 32 raw bytes or 64 hexadecimal digits,
   be a regular private file with mode 0600, and correspond to the source
   AES-256-GCM key. A key mismatch, absent destination secret or damaged seed
   aborts the **entire** PostgreSQL transaction. No active MFA is disabled.
   PostgreSQL methods use the same envelope as the existing HTTP backend;
   migrated enabled TOTP counters are protected by row-locked monotonic updates.

5. Reconcile all release file objects; `files` rows from signed manifests alone
   do **not** mean file bytes exist. For an isolated LocalStorage destination:

   ```sh
   launcher-sqlite sqlite-to-postgres-files --source-root /old/storage \
     --target-root /new/storage --ack-offline
   ```

   For S3, use `--target-s3` instead of `--target-root`, configure the existing
   `LAUNCHER_STORAGE_S3_*` variables (endpoint/bucket/credentials/region), and
   use an isolated destination bucket. Every byte is checked against the
   imported SHA-256 **after readback from the destination**, and existing
   matching files are accepted. Existing conflicting files abort the copy.
   A verified source-specific file-copy receipt is persisted only after all
   objects and the complete files catalog have been checked. Retry a failed
   copy only after fixing the root cause.

## Import behavior

- Core `auth_sessions`, `access_tokens`, `refresh_families`, `refresh_tokens`,
  `mfa_totp`, `mfa_recovery`, `minecraft_profiles`, `minecraft_sessions`,
  `auth_revocation_events`, `durable_jobs`, `durable_job_attempts`,
  `durable_scope_leases`, `durable_outbox`, `bridge_nodes`, `bridge_nonces`,
  `bridge_join_tickets`, `bridge_runtime`, `bridge_runtime_nonces`, and
  `bridge_commands` are mapped to PostgreSQL runtime tables or explicit
  security tombstones. Rows and staging checksums are verified during the
  one-transaction transfer; source identifiers and critical security data
  are retained. Old sessions/tokens are explicitly revoked. In-flight jobs,
  outbox delivery, command execution and runtime leases are fenced or made
  indeterminate; old credentials and workers are not silently revived.
- Re-enrollment is **not** a substitute for migrating MFA: TOTP secrets are
  decrypted using the source private AES-GCM key and immediately re-encrypted
  with the destination API secret. Prior single-use recovery code hashes are
  copied as hashes, preserving their one-use status.
- Active extensions and any other nonempty Core staging tables without a
  supported working SQLRepository mapping **block the transaction**. They are
  not silently skipped and never counted as successful data migration.
- The Core import does **not** migrate `http.sqlite`, `coordinator.sqlite`,
  PostgreSQL-native trusted devices, standalone publication/control-plane
  state, extension package activation, extension configuration or every
  external service's state. A Core import is therefore **not** full service
  parity, even if all imported rows match. This milestone reports
  `readyForBackendCutover=false` intentionally. Operators must retain the
  source files and verify actual API, authentication, project, publish, bridge,
  extension and launcher workflows before using PostgreSQL for production.

## Validation status

This source patch has Go syntax/format checks and regression scenarios, but a
Go 1.27.3 toolchain and integration PostgreSQL instance are not available in
this build environment. Actual PostgreSQL integration, extension compatibility,
cutover, rollback and complete data parity remain **unverified**. Do not
interpret an emitted receipt as production GA acceptance or a successful
end-to-end migration.

# NeverLauncher 0.47.5 — автономный SQLite → PostgreSQL операторские процедуры и безопасность переключения

**Status: source candidate, production cutover BLOCKED by missing source parity.**
The 0.47.4 SQLite Core importer populates PostgreSQL SQLRepository but does
not migrate the separate `http.sqlite` snapshot, `coordinator.sqlite`, all
extension state or every external runtime store. The CLI deliberately does not
turn its `readyForBackendCutover=false` report into a positive certification.
There is no supported flag to override this block. Do not turn on a live
PostgreSQL Backend from these receipts alone.

## что действительно делает оператор

`python3 scripts/operations/sqlite_pg_cutover_0475.py` implements a durable,
local-only operator workflow with private journals, one-owner flock, source
preflight, independent Core restore-proof backup, writer-service stop and
inactive checks, frozen Core/HTTP/Coordinator backup, immutable staging/live
SQLite Core import, verified file transfer and read-only PostgreSQL check.
The Backend now also refuses startup against PostgreSQL that contains a live or staging SQLite import but lacks complete cutover acceptance. This check executes before application bootstrap, extensions, workers, or HTTP listeners. Unrelated PostgreSQL installations with no import are unaffected.

The reader verifies receipt SHA-256, every mapped table's row count (including
special transformations), catalog digest and user/project data from the actual
SQLRepository implementation. Existing old count-only file receipts must be
regenerated with the 0.47.5 copier. Unmapped source state is **not dropped**.

For actual systemd-backed operator execution on an isolated test deployment:

```bash
# Before execution, deploy a Go 1.27.3 launcher-sqlite binary with 0.47.5 changes,
# apply all existing PostgreSQL SQL migrations to an empty destination and
# export LAUNCHER_POSTGRES_DSN and MFA secrets securely.
python3 scripts/operations/sqlite_pg_cutover_0475.py run \
  --work-dir /private/neverlauncher-cutover-0475 \
  --launcher-sqlite /usr/local/bin/launcher-sqlite \
  --source-env /etc/neverlauncher/backend.env \
  --core-db /var/lib/neverlauncher/core.sqlite \
  --http-db /var/lib/neverlauncher/http.sqlite \
  --coordinator-db /var/lib/neverlauncher/coordinator.sqlite \
  --storage-source /var/lib/neverlauncher/objects \
  --storage-target /var/lib/neverlauncher/pg-objects \
  --writer-unit neverlauncher-api.service \
  --writer-unit neverlauncher-worker.service \
  --project existing-project-id \
  --owner-email original-owner@example.invalid

# Review current state. No credentials or DSN are persisted to this journal.
python3 scripts/operations/sqlite_pg_cutover_0475.py status \
  --work-dir /private/neverlauncher-cutover-0475

# Before any PostgreSQL writer has started, recover previous env / SQLite unit.
python3 scripts/operations/sqlite_pg_cutover_0475.py rollback \
  --work-dir /private/neverlauncher-cutover-0475 \
  --source-env /etc/neverlauncher/backend.env \
  --core-db /var/lib/neverlauncher/core.sqlite \
  --http-db /var/lib/neverlauncher/http.sqlite \
  --storage-source /var/lib/neverlauncher/objects \
  --storage-target /var/lib/neverlauncher/pg-objects \
  --writer-unit neverlauncher-api.service \
  --project existing-project-id \
  --owner-email original-owner@example.invalid
```

`LAUNCHER_POSTGRES_DSN` must be present in the operator process environment.
If TOTP is configured, add `--mfa-key-file <0600 file>` and
`--pg-secret-env <variable-name>` to the `run` action. Do not put secret values
into command-line flags. `--writer-unit` must enumerate **all** writer units,
including schedulers and extension/bridge supervisors; anything outside systemd
requires independent fencing before running. The operator cannot prove that an
unknown unmanaged process has stopped writing. A frozen snapshot is taken only
after all the declared units are inactive.

## семантика сбоев

- The operator retains `state.json` and fsynced append-only `stages.jsonl`
  under a private 0700 work directory. A completed stage is skipped when the
  command is resumed. Ambiguous PostgreSQL commit after a crash is **not**
  automatically retried: inspect `sqlite_live_receipts_0473` and reconcile
  manually before new work.
- Original Core, HTTP and Coordinator SQLite files are not mutated by import.
  `rollback` restores the source configuration and restarts its systemd unit
  only when a service has **not** crossed the new-write boundary. A failed run
  attempts this safe rollback automatically once a verified source backup
  exists; an uncertain rollback is logged as a failure rather than success. Frozen
  backups must still pass their integrity checks.
- An unsuccessful import keeps the PostgreSQL destination isolated. A storage
  copy conflict or bad SHA-256 blocks further steps; never advertise success
  based on file counts alone.
- Backend cutover remains blocked until a future release migrates and verifies
  the HTTP Repository, Coordinator, Extensions, persistent security and other
  active state and independently validates user authentication, publish and
  Minecraft execution. A read-only owner/project lookup does **not** prove
  password login, working server-bridge or a complete Minecraft launch.

## приёмка ещё не завершена

Full Go 1.27.3 tests, PostgreSQL integration, actual systemd freeze/restart,
independent restore/HA fencing, owner credential login, API publication,
ServerBridge and real Minecraft E2E were not executed in the authoring
container. Version 0.47.5 is not certified as a production GA cutover.

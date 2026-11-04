# 0.49.1 — аудит работающих Backend / PostgreSQL / Java Host

This is a **running integration test**, not a manifest or a status endpoint test. It does not migrate a Gravit project, publish a release or certify 0.50 GA on its own. It does not modify migration, user, world, extension or release data.

## предварительные требования

- A running **PostgreSQL** NeverLauncher Backend with current SQL migrations, an existing project and a previously created Gravit migration run (the run can still be in `source_assessment`).
- A signed, enabled, **running** Java extension installed in `global` or `project` scope on this Backend. It must expose the already-supported Java Host `health` RPC. The expected host process must be the installation persisted in the same PostgreSQL database.
- Backend admin token with `settings:manage` and `extension:manage` permissions (also the existing authorization policies). Never put the token on a command line.
- An operator-trusted executable `psql` and a read-only PostgreSQL account with `SELECT` on `projects`, `migration_runs_0331`, `extension_installs`. The Backend's normal PostgreSQL DSN is **not** appropriate for a read-only audit account; use a separate least-privileged DSN pointing to the same database.
- A fresh, private output directory. This command refuses to overwrite an existing receipt.

## Выполнение на настоящих установленных службах

```bash
export LAUNCHER_POSTGRES_DSN='postgresql://audit_reader@db.example/launcher?sslmode=verify-full'
export LAUNCHER_MIGRATION_GA_TOKEN='YOUR_EXISTING_ADMIN_TOKEN'
cd tools/migration-ga
GOTOOLCHAIN=local go run . integration-audit \
  --backend https://launcher.example \
  --project my-project \
  --run EXISTING_GRAVIT_RUN_ID \
  --extension example.gravit-module \
  --scope project --scope-id my-project \
  --output /private/evidence/live-audit-0491.json
```

Use `--scope global` (without `--scope-id`) for global Java installations. `--dsn-env` selects a different variable name; `--psql` accepts an explicitly trusted PostgreSQL client binary. `psql` reads the connection string through its `PGDATABASE` environment, not argv. The tool sets read-only transactions and a connect timeout. The output is an **unsigned** local observation, not a substitute for independent receipts or final signed release acceptance.

## Выполненные проверки

1. `/ready` returns HTTP 200 with PostgreSQL repository health and current SQL migrations. The CLI rejects SQLite, unavailable PostgreSQL and schema drift.
2. The authenticated migration API returns the requested run and project, with `sourceKind=gravit`.
3. PostgreSQL transaction reads the exact project, migration revision/status/step and enabled extension installation version/generation. No temporary table or shadow migration store is used.
4. `POST /api/v1/admin/extension-hosts/{extensionId}/probe` executes a real Go → JVM `health` callback, with Backend authorization and **live trust revalidation**, and confirms `RUNNING`, the expected instance and generation.
5. Independent repeat reads reject a concurrent change to a migration or installed Java extension. Failure produces no `passed` evidence file.

The check verifies one consistent observed state at two moments. It cannot provide an atomic distributed snapshot or guarantee that the state will never change after it returns. Use the existing fenced cutover procedures and independent production migration GA runner for that purpose.

## Граница локальной проверки

```bash
(cd tools/migration-ga && GOTOOLCHAIN=local GOPROXY=off go test ./... && GOTOOLCHAIN=local GOPROXY=off go vet ./...)
sh sdk/java/core/build.sh test
```

The tool's HTTP and `psql` mock regression tests prove **failure handling**, not that a real deployment passed. A real PostgreSQL server, Go 1.27.3 Backend, signed installed Java extension and live Gravit project are required before this milestone can be marked independently accepted. The new probe does not grant Java execution or bypass permissions: it permits only the existing health RPC on a running authorized host.

# NeverLauncher 0.37.5: single-host SQLite installation (Linux)

This procedure uses the actual HTTP repository and persisted auth/session stores; it does not set up PostgreSQL or Redis. It is a **single API process** on a supported local filesystem, not network HA. Use a service account that owns the installation directory, and a reverse proxy terminating HTTPS. Never place the SQLite databases on NFS or shared/overlay writable volumes.

## Prerequisites

Build `neverlauncher-api` from the exact release sources with the toolchain pinned by `services/api/go.mod`; obtain a verified executable and the actual `NeverGuard` and `ServerBridge` release allowlist JSON policies for your shipped artifacts. The installer intentionally cannot invent signed release data. If these policies are missing or invalid, startup must fail.

## Install

```sh
python3 scripts/install/minimal-install.py init \
  --root /var/lib/neverlauncher-minimal \
  --binary /opt/neverlauncher/bin/neverlauncher-api \
  --public-url https://api.example.org \
  --guard-policy /etc/neverlauncher/verified-guard.json \
  --bridge-policy /etc/neverlauncher/verified-bridge.json
python3 scripts/install/minimal-install.py check \
  --env-file /var/lib/neverlauncher-minimal/config/backend.env \
  --binary /opt/neverlauncher/bin/neverlauncher-api
python3 scripts/install/minimal-install.py run \
  --env-file /var/lib/neverlauncher-minimal/config/backend.env \
  --binary /opt/neverlauncher/bin/neverlauncher-api
```

The initializer creates private `config`, `db`, `storage`, `backups` and `extensions` directories and writes the initial configuration with mode `0600`. It refuses to overwrite an existing installation. `check` calls the backend's real offline `diagnose deployment` command and stops if release policies, persistent storage or security settings are invalid. `run` replaces the Python process with the API. To enable automatic startup, configure your local service manager to run that command as the dedicated service user; ensure the API binary and Python script are protected against untrusted modification.

Use a TLS reverse proxy for `https://api.example.org`; the API defaults to `127.0.0.1:8080` and is not exposed directly. Read `NEVERLAUNCHER_BOOTSTRAP_TOKEN` only from the private `backend.env`; never include it in a URL, log, issue or public paste. Submit it to `POST /api/v1/install/bootstrap-admin` via the `X-NeverLauncher-Bootstrap-Token` header with a 12+-character admin password. Sign in as that owner, then call `POST /api/v1/install/first-project` with the owner's credentials. `GET /api/v1/install/readiness` shows installation status.

After the administrator is committed, the bootstrap token cannot be reused and restarting with a different value does not re-enable it. Back up the private configuration and signing keys offline, separately from the database. Do not use a filesystem copy of a live `*.sqlite` file as a reliable backup; use the supported online SQLite backup mechanism in the next milestone. The **0.37.6 backup/restore** and **0.37.7 SQLite ↔ PostgreSQL transfer** stages still require their own acceptance and must not be represented as completed by this installer.

## Safety boundaries

- Production rejects a memory repository, missing or malformed release allowlists, weak signing keys, unsafe WebAuthn/CORS origins, Redis/HA selection in minimal mode, and missing fail-closed rate limiting.
- The single-host API holds an exclusive instance lock anchored to its local storage root and SQLite's own database owner locks. Never unlink a held lock file to circumvent fencing.
- SQLite snapshots and runtime state persist under WAL before operations return; stable release publication retains its signed, one-use authorization checks from 0.37.4.
- A successful `check` confirms configuration only. For an operational acceptance, boot the **compiled** API on a supported filesystem, create owner/project, restart it and inspect persisted users, authentication and release policies; perform separate negative tests and signed release verification before claiming GA.

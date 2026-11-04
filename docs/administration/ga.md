# Launcher 0.22.0 — Admin GA acceptance and deployment

**Policy:** Changing `VERSION` to `0.22.0` is not evidence that the release passed
GA. The deployable release is certified only when the exact-commit
`Launcher Production Release Candidate` workflow and all its required
platform, trust and Admin jobs have passed. Do not tag or distribute the source
archive as a certified production release before then.

## Scope

This release completes the 0.21.6–0.21.12 Admin track without changing the
ServerBridge protocol v3 or weakening release signing and server-side RBAC.
Daily operations include project-scoped releases and rollback, durable job
recovery, ServerBridge control/telemetry, devices/sessions, backup/restore,
Extensions, typed live config and server-side audit search.

## Mandatory certification (no mocks / no skips)

Run from a **clean checkout of the intended release commit**, with pinned Go,
Node and Python dependencies, PostgreSQL 16 via Docker and a dedicated staging
installation. Staging must have a ready Backend **and** Admin frontend built
from the **same source commit**, with `sourceCommit` embedded in Backend via
`-X main.commit=<SHA>` and in Admin by `LAUNCHER_SOURCE_COMMIT=<SHA>`
when Vite builds. CI Docker/release build paths propagate this build-time identity. The script checks the source commit against the
caller-supplied `LAUNCHER_GA_SOURCE_SHA` and fails if the checkout is dirty.

```bash
export LAUNCHER_GA_SOURCE_SHA="$(git rev-parse HEAD)"
# Set E2E_ADMIN_URL, E2E_API_URL, E2E_PROJECT_ID,
# E2E_FOREIGN_PROJECT_ID, E2E_ADMIN_TOKEN and E2E_OPERATOR_TOKEN
# to disposable staging fixtures (never check credentials into source).
# Also set E2E_SERVERBRIDGE_NODE_ID to an actively running disposable
# Minecraft ServerBridge v3 node and E2E_DESTRUCTIVE_STAGING_ACK
# to exactly I_CONFIRM_DEDICATED_SERVER before running drain/undrain.
bash scripts/release/certify-admin-ga-0220.sh
```

The runner actually executes, and fails on any nonzero result:

1. `python3 scripts/release/check-admin-ga-0220.py`: version, canonical OpenAPI,
   repository safety checks, SHA-256 equality of **all** immutable migration
   files in Backend and CLI, and full deterministic regeneration of 16 SDK
   artifacts. It does not rewrite historical SQL migrations.
2. `npm ci`, all Admin Node tests and `tsc && vite build` to a deployable Admin
   bundle.
3. Backend and CLI full `go test -race -count=1 ./...`, `go vet ./...` and
   production Go builds.
4. `e2e/scripts/run-admin-hardening-02112-e2e.sh` in real PostgreSQL (pgx):
   concurrent config compare-and-swap, migrations, durable job recovery,
   ServerBridge v3 enqueue/lease/ACK, inter-project access tests.
5. `e2e/scripts/admin-hardening-02112-browser.py` against **real staging**:
   actual Backend readiness/version/**source commit**, Admin version/source commit, two tabs editing the same
   revision, network loss/reload, cross-project forbidden reads and login
   accessibility labels. A test account and second inaccessible project must
   be provisioned. The test may create/delete its own draft only.
6. `e2e/scripts/admin-ga-0220-serverbridge.py` against an **actual disposable
   Minecraft server with ServerBridge v3**, using a freshly MFA-authenticated
   operator. It requires exact server ID and an explicit destructive-test
   acknowledgement. It runs save, drain and undo-drain, waits for real
   successful ACKs, and checks that identical idempotency keys do not enqueue
   duplicate commands. `pending` or `leased` are **not** success. If ACK or
   undrain fails, GA certification fails; investigate the staging server.

After **all** stages succeed, the runner writes
`dist/ga-certification/admin-0220.json` with commit, source contract hash and
built Admin asset hashes. Absence of this file means no GA certification.
This JSON is test evidence, not a cryptographic signature, and does not replace
product-wide platform/signing certificates.

GitHub Actions `.github/workflows/production-release-candidate.yml` requires
this result from `admin-ga-certification` after the complete base CI succeeds,
and verifies the certificate's commit and version before bundling. Other
required production certifications and signed artifacts remain independently
mandatory. A missing staging URL, token, Docker, dependency, proof, or passing
test **blocks** release; there is no fallback to unit-only or mocked tests.

**Provenance limit:** the live probe validates the source commit ID **embedded
at build time** in both Backend and Admin; this establishes build identity
consistency but is not a cryptographic attestation on its own. Signed build
provenance from the release pipeline and trusted staging deployment are still
required. Do not treat a manually spoofed commit string as release proof.

## Operational acceptance matrix

| Exit requirement | Certification proof |
|---|---|
| Release-manager publishes and rolls back own project only | Project RBAC tests, release operations tests, live restricted-project denial |
| Operator drains and saves world without shell | ServerBridge v3 integration plus live `server.save`, `server.drain`, undrain, signed ACK and replay against a disposable Minecraft server |
| Jobs survive browser disconnect and replay remains idempotent | Admin network tests, PostgreSQL durable tests and real browser recovery |
| User-facing access/field/server refusal is actionable | Structured error tests, Admin UI tests and manual UAT |
| Sessions, devices, restore and extensions have confirmations and audit links | Admin test suite and manual staging UAT of destructive operations |
| Config CAS and restore-as-new-revision | PostgreSQL concurrent revision test and two-tab browser CAS test |
| Docs, SDK, migration parity and production build | Source audit, SDK regeneration, both SQL directories, tsc/Vite and Go builds |

**Manual UAT is additionally required** for actual player kick/broadcast,
backup/restore with
disposable real data, step-up/MFA, passkeys, extension host lifecycle and
keyboard/screen-reader accessibility. Automations listed above do not
constitute proof of these physical/interactive scenarios by themselves. Record
evidence on the release issue before production approval.

## Deployment and rollback

1. Back up PostgreSQL and object storage. Verify the restore procedure on an
   isolated instance. Check active sessions/jobs and ServerBridge health.
2. Test SQL migration upgrades from the deployed schema with Backend and CLI
   migration tools. **Do not edit applied migration files**, or run the CLI
   with a migration catalog older than Backend. Upgrades through
   `0055_config_audit_02111.sql` must be applied and verified before traffic.
3. Deploy the certified API, Admin and CLI for the *same release commit*;
   verify `GET /ready` returns `ready`, `GET /api/v1/status` returns `0.22.0`
   and the expected `sourceCommit`, and the Admin footer displays `0.22.0`
   with the correct source commit embedded in its page metadata.
4. Exercise RBAC on two disposable projects, check publish/rollback and
   ServerBridge command acknowledgements, audit correlation, config history,
   and job recovery in a staging/sandbox project before enabling production.
5. To roll back a failed **application** deployment, restore the previous
   application build and its compatible schema, **not** blindly down-migrate
   the database. Do not run an older Backend or CLI against newer unknown SQL
   migration versions. Use tested backup/restore for incompatible rollback;
   preserve job idempotency records and audit trail. Release channel rollback
   is a separate durable operation and does not restore database schema.

## Unverified locally

On machines without npm/Go modules and Docker, static checks may pass while the
mandatory full production, PostgreSQL/ServerBridge and browser gates remain
**unexecuted**. In that case 0.22.0 source is a *candidate*, **not certified GA**.

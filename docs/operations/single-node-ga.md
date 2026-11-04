# Launcher 0.33.0 — Production Single-Node GA release & operations

## Release status and supported deployment modes

**Do not advertise or publish this version as independently certified GA until the
real SQLite-only HTTP Backend has been completed and tested.** The previous
0.32.16 source still uses PostgreSQL for the HTTP Repository and rejects
SQLite-only HTTP. Existing SQLite Core/Coordinator operations and a passing
CLI test suite do not establish a production single-node deployment.

| Mode | Runtime | Supported in provided baseline | Release gate |
| --- | --- | --- | --- |
| Standard, single API process | PostgreSQL + SQLite WAL coordinator + local blobs | Existing implementation (integration validation required) | Existing RC/security/deployment tests |
| SQLite-only production Single-Node | SQLite WAL for **all** Backend Repository state, SQLite coordinator, local blobs, no PG/Redis | **Not implemented in HTTP Backend** | **0.33.0 GA blocked** |
| Network/HA | PostgreSQL + Redis + shared S3, multiple independent workers | Infrastructure checks exist; multi-host failover unproven | Independent HA certification, not covered by single-node GA |

The 0.33.0 release toolchain **intentionally fails closed** when the required
single-node evidence is absent. It does not turn the SQLite coordinator into
an alternative HTTP Repository, perform unsupported SQLite→PostgreSQL cutover,
or bless an untested HA topology.

## Production prerequisites

- Install on dedicated Linux host with a supported local ext4/XFS/Btrfs filesystem
  (not NFS/SMB, container overlayfs, or multiple shared writers). Dedicated
  service identity and restrictive private state directory (`0700`).
- Pin the exact signed installer, API, Admin, Desktop, Guard, Runtime and plugin
  versions using `RELEASE_BOM.json` and release trust policy; never use mixed `latest`.
- Use HTTPS, valid Guard and ServerBridge trust allowlists, securely generated
  signing/auth keys, and independently held offline backup copies. Never
  commit secrets, identities or operator attestation signing keys to this repo.
- Complete the actual SQLite-only HTTP repository implementation and deploy
  it in an isolated acceptance environment. **Until then, run Standard with
  PostgreSQL** as described in `docs/releases/0.32.13-production-deployment.md`.

## Live acceptance before GA signature

Run the 0.33.0 RC gate on a native filesystem with real PostgreSQL, Redis, S3
and SQLite CI fixtures (not live customer data):

```sh
python3 scripts/version/manage.py check
python3 scripts/rc/production_rc.py --output /secure/evidence/SINGLE_NODE_GA_RC.json
```

The RC gate verifies specific real Go tests with `-race`, requiring all tests
PASS and a full 0.33.0 Git commit. Skips, missing names, unavailable dependencies,
failed assertions and timeouts **block** certification. The reported throughput
of a synthetic fixture is not a measured production capacity limit.

A separate qualified operator must run and independently sign a complete **live
installed deployment report**. It must contain the literal observations:
SQLite HTTP repository, SQLite coordinator, WAL, one Backend, verified native
local filesystem, persistence across restart, and absence of PG/Redis dependencies.
The report also needs passing observations of all 13 scenarios:

1. Signed installer and exact signed release BOM validation
2. Fresh install and owner bootstrap
3. Admin login, authorization/RBAC and permissions
4. Stable player Minecraft UUID, login and successful server join
5. Ticket one-time consumption and replay rejection after restart
6. MFA and token revocation after restart
7. Jobs, outbox idempotence, fencing of stale workers
8. SQLite WAL crash, backup and restore integrity
9. Verified pre-upgrade snapshot, upgrade and rollback
10. Rejection of second Backend opening the same store
11. Negative signature, permission and security tests
12. Measured representative capacity and declared limits
13. Executed operator runbook smoke

The signed report is an externally produced JSON document, never generated
as a passing fixture by the release pipeline. Its format is checked by
`scripts/ga/single_node_ga_0330.py`: `schema` equals
`launcher-single-node-ga-attestation-v1`, `version` equals `0.33.0`,
`source_commit` equals the exact full Git SHA, `rc_receipt_sha256` equals the
real RC file digest, `operator` identifies the independent verifier,
`environment` has the required observed values, `checks` maps **all 13**
scenario IDs to `pass`, and `tested_artifacts` pins three SHA-256 digests:
`launcher-api-linux-x64`, `launcher-cli-linux-x64`, and
`launcher-linux-x64-0.33.0.tar.gz`. The release builder and verifier
compare those hashes to the exact shipping artifact bytes, blocking
substitution of an untested build. The operator signs the **exact raw JSON bytes** with
a separately controlled Ed25519 key. The detached `.sig` contains the base64
signature. The matching public key must be provisioned out of band and must
be **different** from the release signing key.

Sample verification (will fail unless actual approved evidence exists):

```sh
python3 scripts/ga/single_node_ga_0330.py \
  --evidence-dir /secure/evidence \
  --public-key /secure/trust/independent-ga.pub \
  --commit "$(git rev-parse HEAD)" \
  --output /secure/approved/SINGLE_NODE_GA_CERTIFICATION.json
```

Required exact filenames in `/secure/evidence`:
`SINGLE_NODE_GA_ATTESTATION.json`, `SINGLE_NODE_GA_ATTESTATION.sig`,
`SINGLE_NODE_GA_RC.json`. A certificate derived from a fixture or self-signed
by the release signing key does not constitute GA evidence.

## Building, verifying, publishing

`production-release-candidate.yml` requires independent signed evidence from
an approved same-commit workflow dispatch and compares the embedded RC receipt
byte-for-byte against the RC job of the current workflow. Its protected
`production-release` environment must approve release signing; no secret
private key is embedded in Git, release artifacts or CI test fixtures.

From a clean, committed checkout, set the existing release signing/trust
variables and additionally:

```sh
export LAUNCHER_SINGLE_NODE_GA_EVIDENCE_DIR=/secure/evidence
export LAUNCHER_SINGLE_NODE_GA_PUBLIC_KEY_FILE=/secure/trust/independent-ga.pub
bash scripts/release/build-release.sh
```

The release builder **verifies evidence before deleting old output** and copies
all four GA files into the bundle (including its freshly derived verification
receipt). BOM, `RELEASE_MANIFEST.json`, `SHA256SUMS` and Ed25519 release signing
bind these exact files **and** require the independently tested Linux binary
and distribution archive digests to equal the shipped files. The CLI `release build`, `release sign`, `release
verify` and `release publish-check` independently check GA evidence and reject
missing/altered reports. Consumers must supply an independently pinned GA
public key in addition to the normal release root/trust policy:

```sh
export LAUNCHER_SINGLE_NODE_GA_PUBLIC_KEY_FILE=/secure/trust/independent-ga.pub
launcher release verify /secure/release-0.33.0 \
  --public-key /secure/trust/release-root.pub \
  --trust-policy /secure/trust/release-trust.json
launcher release publish-check /secure/release-0.33.0 \
  --public-key /secure/trust/release-root.pub \
  --trust-policy /secure/trust/release-trust.json
```

If external evidence, commit, independent key, CI, BOM, release artifacts,
or signed delivery approval are missing, **do not publish** and do not substitute
stubs, downgraded modes, disabled tests or memory fallbacks.

## Standard operating procedures (currently supported runtime)

- **Before install:** provision TLS, PostgreSQL, the SQLite coordinator's
  durable directory, signed release, S3/local blobs and approved policies.
  Validate production `.env` permissions (`0600`) and server clock accuracy.
- **Start:** `python3 scripts/install/production-deploy.py compose check --mode standard`
  and then `... compose up --mode standard`; confirm health, readiness,
  logs, auth, admin and a real player join. Do not expose plaintext proxy ports.
- **Observe:** `launcher-api diagnose capacity`, `/metrics` through
  authorized monitoring, queue/outbox age, disk headroom, HTTP p95/error rate,
  PostgreSQL connections and SQLite coordinator WAL/storage growth. Published
  capacity ceilings need target-host load measurements; synthetic RC tests do
  not produce them.
- **Backup:** perform independent encrypted, off-host, restorable PostgreSQL
  and local blob backups; use `launcher-sqlite pre-upgrade` for the SQLite
  coordinator/Core where applicable. Validate restore to an isolated host.
  Never assume SQLite backup also backs up PostgreSQL or blobs.
- **Upgrade:** pin the same BOM cohort, drain commands, record source/current
  version, snapshot durable state, verify restore, upgrade only one revision
  at a time and confirm authentication, revocation, Minecraft UUID and join
  invariants. If any check fails, stop traffic and follow tested recovery.
- **Crash/incident:** fail closed on signature, replay or fencing errors;
  isolate the host, preserve DB, WAL and logs for forensics, restore only from
  verified backup and re-check revocation and nonce reuse after restart.
- **Uninstall:** `python3 scripts/install/production-deploy.py ...` preserves
  data by default. Deleting durable state requires a separate, explicit
  confirmation and independently verified off-host backups.
- **Growth:** 0.33.0 cannot yet be used as proof of lossless SQLite→PostgreSQL
  live cutover. Staging migration and row/hash checks are **not** activation.
  Schedule a separately validated cutover and player UUID/revocation testing;
  do not switch DSNs and assume continuity.

## Evidence, reproducibility and release limitations

Run the verifier regression tests without external accounts:

```sh
python3 -m unittest discover -s scripts/ga -p test_single_node_ga_0330.py -v
python3 -m unittest discover -s scripts/rc -p test_production_rc.py -v
```

The fixture tests generate ephemeral signing keys and test failure handling;
**their PASS result does not authorize GA**. Current source work does not
include actual certified 0.33.0 installer artifacts, a signature from an
independent operator, demonstrated HTTP SQLite Repository integration, or a
multi-host failover certificate. Those cannot be inferred from a source ZIP.

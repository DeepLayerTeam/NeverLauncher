# NeverLauncher 0.53.0 — Full Real User Acceptance GA

This release changes **working** release admission code. It does not assert that
external tests have already completed. Until the protected workflow executes
on the actual signed release, the 0.53.0 GA decision is **BLOCKED**.

## Mandatory independent acceptance

The pre-existing `defect_rehearsal_05212.py` is now current-version bound.
For 0.53.0 it freezes the exact clean Git source and six final installers,
verifies the separately pinned distribution index and detached Linux
signatures, re-executes regressions, accepts only an independently signed
complete P0/P1 closure export and replays the complete **original** 280 required
Minecraft/JVM/loader/real-join receipts, six native final package installations,
six native games, five one-hour Minecraft soaks, one-hour HTTP load ledger,
and two separately signed independent six-target unsigned builds. Failure or
missing raw evidence is BLOCKED, never optional or automatically skipped.

`full_real_acceptance_0530.py` *also executes* these live suites on the
independent physical/game QA lab. It does not invoke an arbitrary user-supplied
program or `sh -c`, accept `--help` as a PASS or treat a `status: passed`
report without a subprocess completion and hashed logs as execution. All
result files and bounded original process logs are stored privately; the
independent verifier checks source, final packages, issue authority, full
sweep, original logs and strict scenario-specific success conditions.

| Mandatory user scenario | Actual executable and required observation |
|---|---|
| E2E-01 Clean installation | Minimal `minimal_live_e2e_0378.py` and Standard production `owner_admin_real_0523.py` |
| E2E-02 Owner daily work | Real Standard Admin, project, profile/channel, MFA and RemoteControl lifecycle |
| E2E-03 Minecraft loaders | 280 genuine required client/loader/server targets, including actual join |
| E2E-04 Optional components | `modpacks_textures_publication_0526.py`: selected/unselected JAR, repair, dependencies |
| E2E-05 Official login | `auth_identity_real_0525.py run`: real Microsoft/Xbox/XSTS/Mojang join |
| E2E-06 Identity and roles | Local/SQL/OIDC canonical identity, linking/UUID, role, replay/revoke |
| E2E-07 Skins and capes | Real PNG upload/readback and published game materialization |
| E2E-08 Gameplay | Real client and matching-server join plus published modpack launch |
| E2E-09 Publication validation | Actual release validate → sign → stage → integrity → publish |
| E2E-10 Install/repair/rollback | `install_upgrade_repair_0527.py` with network, corruption and physical ENOSPC |
| E2E-11 Java customizations | `java_sdk_migration_0528.py live`, five real trusted Java cases |
| E2E-12 Gravit migration | Three actual projects, 36 migrations + 19 module checks |
| E2E-13 Historical NeverLauncher | Live migration 0.36.0 and 0.46.0 preserving identity/data |
| E2E-14 Physical HA/DR | Separate real Redfish host, routed nftables partition, Patroni, Redis, S3 and fenced-world recovery |
| E2E-15 AntiCheat/Guard | `guard_device_bridge_real_0529.py live`: live Guard + shadow, 7 Device Trust, 14 Bridge targets at declared levels |
| E2E-16 HTTP SDK | `sdk_live_0530.py`: real Go, TS and Java SDK against same HTTPS Backend, JSON, text, binary SHA-256/stream |
| E2E-17 Final delivery/build | Frozen six signed installers, native games, two independently signed builders, soaks |
| E2E-18 Release evidence | Complete 18-group executed map + signed QA and separate verifier replay |

The ServerBridge matrix continues to distinguish 10 runtime E2E adapters,
three JAR/build-compatibility targets and the Vanilla sidecar/RCON target.
A build-only target is not silently promoted to runtime support.

## Secure lab handoff and proof origins

The protected `.github/workflows/full-real-ga-0530.yml` has three distinct
machine roles plus an ordinary regression job. The release-freeze machine
receives six original final installers and the independently approved index
hash. Only a clean Git checkout of the exact approved commit can be frozen.
The issue export comes from the actual issue tracker with a **different**
Ed25519 authority. Empty or fabricated tracker exports are not proof of
closure; the organization must restrict the issue signer to an audited,
complete tracker export.

On the independent QA machine, provision:

- `packages/` and `source-index.json` from the real distribution, not newly
  compiled on QA; `issues.json`/`issues.sig`, `full-sweep-paths.json` (as in the
  0.52.12 runbook), and a private `live-plan.json` in the QA inbox.
- `live-plan.json` is private 0600 JSON with **exactly** `version`,
  `sourceCommit`, `sourceIndexSha256`, and `scenarios`. `scenarios` has the 14
  exact keys `minimal`, `standard`, `auth`, `modpacks`, `install`, `java`,
  `guard`, `sdk`, `ha-host`, `ha-partition`, `ha-postgresql`, `ha-redis`,
  `ha-s3`, `ha-world`. Each value is an argv string array of the real
  underlying executable, **without** program name and without
  `--report`/`--output` (the GA runner chooses exclusive destinations). For
  `auth`, begin with `run`; for `java`/`guard`, with `live`; for HA, use the
  fixed mode enforced by the runner. Inspect the original `--help` of each
  executable for the real operator arguments. No placeholder reports or
  simulated endpoints may be supplied.
- The physical HA targets must be dedicated disposable hosts with separate
  BMC management, working recovery route, real Alertmanager delivery and
  real fenced Minecraft world. The operator explicitly authorizes outages.
  An unfinished recovery or missing real Minecraft player keeps GA blocked.
- Official OIDC authorization proof expires after 600 seconds. Generate it
  against the real issuer just before the actual `auth` invocation; do not
  try to bypass expiration or pre-populate a synthetic success. A protected
  interactive operator workflow can be used for the live-review stage.
- The SDK runner requires a pinned, real HTTPS Backend with a privately held
  0600 Bearer token, JSON endpoint, plaintext endpoint and binary endpoint
  (PNG or ZIP) plus its **out-of-band** SHA-256. It executes the production
  Go/TS/Java clients. Existing local mock SDK unit tests alone cannot pass.

Private raw logs, world backups, credentials, native evidence and lab-plan
are transferred to the **independent verifier** by a secured external channel.
Never include private keys, Microsoft tokens, OIDC authorization codes,
RCON credentials, player identity secrets, or world data in public GitHub
artifacts. Preserve only nonsecret signed decisions in public artifacts.
QA and verifier must have different Ed25519 keys, and neither may reuse the
release or issue-export key. Pins are configured independently from the files
being checked.

## Release decision and publication

`full_real_acceptance_0530.py review` runs real live suites and signs
`qa.json`/`qa.sig` with the QA authority. The independent verifier calls
`approve` on the **original transferred evidence**, re-runs all fixed
regressions and raw 280/native/soak/build validators, checks unchanged logs
and results from every scenario, and signs `approval.json`/`approval.sig`.
Only the final independent report may have `status: PASS`; a QA-only result
is explicitly **not GA**. `release-gate` rechecks both signers and original
inputs before returning exit 0.

The existing production publisher (`scripts/release/publish_0370.py`) now
**refuses version 0.53.0** unless its protected environment provides the
independently signed approval and all six originally approved packages.
`publication_ga_0530.py` verifies the distinct verifier key pin, the source
commit, all 18 groups, the out-of-band index hash, and that the **actual
release bundle** contains byte-identical approved installers. Failure is a
hard error *before* the GitHub network write. The old bundle's own signed
`SHA256SUMS`, `RELEASE_MANIFEST.json`, and other existing publication gates
still apply. **If the current signed-release bundle builder does not include
those six exact files, the 0.53.0 publication remains blocked:** do not
rebuild, swap artifacts or weaken this check to get a green workflow.

The original source ZIP has no Git history or external evidence. Source
code checks are not physical acceptance and do not authorize a real GA release.

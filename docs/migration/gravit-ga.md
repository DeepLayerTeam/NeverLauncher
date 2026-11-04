# NeverLauncher 0.50.0 — Gravit Migration & Module Parity GA

## Definition of acceptance

`VERSION=0.50.0` is not certification. **GA is blocked until external, independently verified evidence exists for three distinct real Gravit projects, all 36 migration checks, all 19 module checks, signed installable 0.50.0 packages and real rollback drills.** A `go test` PASS, signed schema, mock, module registration or a JSON fixture is not such evidence.

The executable checks are composed from the existing real implementations, not a replacement migration backend:

1. `tools/gravit-port/rehearse_cohort_04910.py`: source-pinned import and real Minecraft pre-update launch/login/join, transactional signed client update, second real launch/join, stable UUID and world/player snapshots. The result is `cohort-04910.json`, with immutable raw `pre-update-live.json`, `post-update-live.json`, `signed-update.json` per reference class.
2. `tools/migration-ga`: 10 FileAuth, 14 SQL/modded and 12 proxy/network checks, signed Ed25519 certification, world/player/plugin snapshot comparison, preserved actual check outputs and **live** Backend/PostgreSQL cutover validation. The three distinct real archives, project IDs and run IDs must match the 0.49.10 cohort. `verify-cohort-live` rejects changed/revoked/rolled-back state. Exact supported Gravit source release versions for this gate are currently 5.7.0 through 5.7.12; do not silently certify 5.7.13.
3. `tools/gravit-port/ga_acceptance_0500.py`: checks the original ZIPs, joins before and after signed updates and runs **19 separate hash-pinned module behavior test executables** against the actual migrated reference projects. Each must produce at least two observed behaviors and a newly generated, SHA-256-matched raw evidence file. All modules M01–M19 are mandatory, including M17's safe administrative alternative instead of untrusted arbitrary-code execution. The tool retains raw evidence under a private directory and re-reads the live Backend again after modules finish. It cannot infer real behavior from the `module-parity-04211.json` matrix or mark an untested module supported.
4. Independent review: the reviewer must actually inspect executable test bodies, raw logs, signed packages, the 0.49.11 production cutover and 0.49.12 restore/rollback drills, relevant authority boundaries, identity, Minecraft, plugins, worlds and negative tests. They sign an approval **outside the build/test process** using a distinct Ed25519 key, over hashes of every file in the release evidence directory (including all 19 module evidence files and all six signed packages). Reviewer identity must differ from each Migration GA review identity. This external approval is not created by the code.
5. `scripts/release/ga_gate_0500.py`: validates the detached independent approval, every file digest, original reviewer independence, full six-target installable release via the existing delivery verifier, and repeats the *live* three-project Backend validation after approval. Stale evidence (over 72 hours), revocation, package mismatch or missing module proof blocks release.

## Operator execution

On a protected, isolated, real Linux runner with a working Backend/PostgreSQL, 3 real Gravit source projects and game nodes, verified Microsoft account where required, HAProxy/systemd, three OS desktop runners, real test module services and signed published packages:

```bash
# First run the existing three-project rehearsal and migration-ga certify
# procedures documented in gravit-cohort-rehearsal.md and
# gravit-migration-ga.md. Retain original unredacted results privately.
# Compile the real Go verifier using pinned toolchain:
go -C tools/migration-ga build -o /srv/gravit-ga/migration-ga .

# Write /srv/gravit-ga/config-0500.json as 0600. See required fields below.
# Create an EMPTY 0700 directory; do not reuse a prior acceptance run.
install -d -m 700 /srv/gravit-ga/acceptance-0500
export LAUNCHER_MIGRATION_GA_TOKEN='<short-lived-admin-token>'
python3 tools/gravit-port/ga_acceptance_0500.py \
  --config /srv/gravit-ga/config-0500.json \
  --evidence-dir /srv/gravit-ga/acceptance-0500
```

The tool does not accept 19 status declarations. For each of M01–M19 it **executes a real, pinned standalone test process** and expects JSON on stdout with `moduleId`, `runId`, `projectId`, `sourceSha256`, `passed: true`, `observations: ["...", "..."]`, `evidenceFile` (absolute) and `evidenceSha256`. The file must have been produced during that same invocation. Test binaries must exercise the actual provider, Runtime, client, Discord/Sentry/mDNS/systemd integration, server/JVM host or explicit trusted substitute, and record the observed before/after effects. Registration, static JAR scanning and test-mode mocks do not qualify. Module probes do not inherit the Migration GA bearer, signing keys or DB DSN; use scoped test identities configured separately on the isolated runner.

The private configuration object uses `format: "never/gravit-acceptance-0500/v1"`, absolute `rehearsalRoot`/`rehearsalReport`, `checker` (compiled binary) and `checkerSha256`, `trustedPublicKey` (Migration GA Ed25519 PEM), `references` by `fileauth-single`, `sql-modded`, `proxy-network` (each `plan`, `certificate`, `evidenceDir`, all absolute), and `modules` by `M01` through `M19` (each `referenceClass`, `executable`, `executableSha256`, `args` string list, `timeoutSeconds`). The tool fails closed if a field or required result is missing, source hashes differ, signed E2E evidence is stale, the JVM/module executable changes, the game executable is unchanged after update or active release is revoked. It does **not** create signed packages or mint approval.

Copy the original `signed/` directory containing actual 0.50.0 `RELEASE_MANIFEST.json`, `DELIVERY_VERIFIED_0462.json` and six final signed installers into the completed acceptance evidence root, without replacing any witness. Have an independent reviewer (not the original migration operator) sign an external JSON document with fields `schema: "neverlauncher.gravit.ga0500.independent.v1"`, `version: "0.50.0"`, `reviewer`, `commitSha`, `targetReleaseSha256` and `files` (map of **every** file's relative POSIX path to SHA-256 under the evidence root). The detached Ed25519 signature signs the exact approval JSON bytes prefixed with the ASCII domain `neverlauncher.gravit.ga0500.independent.v1\0`. Store the approval, raw 64-byte signature and trusted raw 32-byte public key *outside* the evidence root, privately. A reviewer should verify raw receipts and make a separate release decision; this tool does not decide whether observations really measure expected Gravit behavior.

```bash
python3 scripts/release/ga_gate_0500.py \
  --config /srv/gravit-ga/config-0500.json \
  --evidence-root /srv/gravit-ga/acceptance-0500 \
  --approval /srv/gravit-ga/external-review.json \
  --signature /srv/gravit-ga/external-review.sig \
  --trusted-reviewer-key /srv/gravit-ga/external-review.pub
```

Or use the protected `.github/workflows/gravit-ga-0500.yml` twice: `witness` to run actual live probes, then, after *out-of-band independent review and signing*, `promote` to verify the same final bytes. Runner variables `GA0500_CONFIG`, `GA0500_EVIDENCE_ROOT`, `GA0500_REVIEW_APPROVAL`, `GA0500_REVIEW_SIGNATURE`, `GA0500_REVIEW_TRUSTED_KEY` are **absolute paths to separately provisioned private files**, not paths populated from build outputs; the admin token is a protected secret. No raw evidence is uploaded to CI artifacts. A missing external system, reviewer or runner is **BLOCKED**.

## Boundary and remaining work

The 0.49.12 file restore tool recovers only verified local world/player/config files, **not PostgreSQL, plugin databases or S3**. Before declaring Gravit cutover/return complete, independent operators must prove fenced writers, HAProxy routes across reload/restart (runtime socket changes are ephemeral), real database and plugin restoration, post-return UUID/players, all signing/trust scopes and native packages. The 36-check `operational-rollback-drill` and `negative-rollback` checks must use those real scenarios; canned success JSON is invalid. The safe alternative to arbitrary `UnsafeCommandPack` execution is separately audited, not literal unsafe binary compatibility.

Passing the *local* tests of the two new tools validates gate behavior and failure handling only. In an environment lacking the real source installations, servers, signed assets, OS runners or independent reviewer **there can be no 0.50.0 production GA certification**.

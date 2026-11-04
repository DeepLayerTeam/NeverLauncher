# NeverLauncher 0.51.0 — Client Guard independent GA procedure

**This release is BLOCKED until the listed tests have run on the actual final signed packages.** An uploaded source ZIP, green unit tests, cross-build, synthetic player hours, signed manifest or an approval from the release publisher is insufficient. The scripts in this change implement the *enforcement and actual native acceptance path*, not a claim that the independent tests have happened.

## 1. Required final-byte evidence

Prepare an evidence directory (without credentials, personal data or signing keys), using exact unmodified outputs from separate native hosts. The file paths below are consumed by `scripts/guard_ci/guard_ga_0510.py`:

```text
evidence/
  signed/                         # exact six final signed installers + manifests + signatures, copied as bytes
  native-signed/
    windows-x64.json              # output of native_signed_0510.py on the actual Windows x64 host
    windows-arm64.json
    linux-x64.json
    linux-arm64.json
    darwin-x64.json
    darwin-arm64.json
  native-game/                    # six raw v10-native-*-gui-<CI_RUN_ID> folders, not a summary alone
  adversarial/<target>/
    result.json                   # captured run-jvm output for the exact target
    logs/*.log                    # exact test output bytes, hashes checked
  performance/<target>/
    baseline/capture.json         # Guard OFF; actual instrumented Minecraft scene
    baseline/frames.csv
    guard/capture.json            # Guard ON; same scene, OS/CPU/GPU/game build
    guard/frames.csv
  real-game/<target>/<loader>/
    run-identity.json             # exact {target, version, loader, packageSha256, username, commit}
    result.json                   # authentic Minecraft E2E result with actual join
    runtime-launch-minecraft.json
    paper.log                     # authenticated ServerBridge admission and player joined the game
    ...                           # the real evidence files named in result.json
  shadow/guard-shadow-<bootId>.jsonl  # raw HMAC-chained PostgreSQL/ServerBridge observations
  shadow-reviews.jsonl            # independent review of EVERY revocation
  shadow-certification.json       # independent legitimate-player-hours review; not auto-generated
```

`<target>` must cover exactly `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`. `<loader>` must cover Vanilla, Fabric, Quilt, Forge and NeoForge, all on **actual installed and launched** packages. Full gaming smoke + adversarial native outputs are checked by the existing `verify_six_native_game_0440.py` against the exact commit, package ID and CI run.

All files in `evidence/` (including the six release assets) must be signed in one independent review inventory. Store the detached `approval.json` and `approval.sig` **outside** the inventory to avoid circular file hashes. The reviewer key must remain external to the release, test runners and source tree.

## 2. Native signature capture

On each **physical/native** Windows, macOS or Linux host with publisher trust anchors installed externally, run:

```sh
python3 scripts/guard_ci/native_signed_0510.py \
  --target linux-x64 --bundle /path/to/exact-final/signed \
  --commit <40-lowercase-source-commit> \
  --expected-signer <trusted-publisher-identity> \
  --operator native-operator-linux-1 --execution-id <unique-run-id> \
  --release-cli /secure/launcher-cli-linux-x64 \
  --release-public-key /secure/release-root.pem \
  --trust-policy /secure/release-trust-policy.json \
  --operations-public-key /secure/independent-operator-public.pem \
  --output /evidence/native-signed/linux-x64.json
```

The executable verifier checks the *actual final bundle* through the production CLI; on Windows it independently invokes Authenticode chain/timestamp validation for the actual extracted EXE/DLL payloads, and on macOS it checks `codesign`, Gatekeeper and stapled notarization for the actual app. Linux requires the production CLI's cryptographic release and distribution verification against externally trusted roots. Each report includes the SHA-256 of the final archive and final release manifest.

Both performance `capture.json` files must additionally include the identical `packageSha256` of the final signed installer; `buildSha256` continues to identify the installed Minecraft build itself.

For each real modded/vanilla game run, use `capture_game_0510.py` on that actual native host after the normal Minecraft E2E completes; it validates the Paper join and existing game logs **before** writing `run-identity.json`, and refuses a different final installer. Never edit `run-identity.json` by hand.

Run JVM adversarial regressions with `adversarial_pilot_05012.py run-jvm` on each target. Run the existing native Minecraft E2E on all six platforms and additionally the real Minecraft loader-specific E2Es. Signed policies must allow explicitly selected Java agents and class transformers; unknown classes/JARs/native modules must remain blocked. Obtain real ON/OFF frame captures, not synthetic arrays. The server shadow pilot must cover **at least 10,000 independently reviewed legitimate player-hours**, with all potential false-positive revocations investigated before auto-sanction eligibility.

## 3. Independent off-host approval

An **independent reviewer** confirms installed gameplay, hashes, incident reviews, native signing, provenance and operator identities; the reviewer is not the release publisher or any platform test operator. The reviewer signs exactly the complete observed directory with a dedicated, previously pinned Ed25519 private key:

```sh
python3 scripts/guard_ci/reviewer_sign_0510.py \
  --evidence-root /evidence --private-key-pem /secure/reviewer-private.pem \
  --reviewer independent-reviewer-2 --release-operator release-publisher-1 \
  --commit <40-lowercase-source-commit> \
  --approval /review/approval.json --signature /review/approval.sig
```

This signing command does **not** itself certify checks. The independent reviewer must inspect genuine outputs and sign only after all external tests have been executed. Re-sign when any evidence byte changes. The approval is valid for at most 72 hours under the verifier's timestamp policy; the independent public key is pinned by production release configuration.

## 4. Final release gate

On the production release host, with access to the *same exact signed bytes that will be published*, run:

```sh
python3 scripts/guard_ci/guard_ga_0510.py \
  --evidence-root /evidence --approval /review/approval.json \
  --signature /review/approval.sig --trusted-reviewer-key /secure/reviewer-public.raw \
  --commit <40-lowercase-source-commit> --release-operator release-publisher-1 \
  --native-package-id <exact-staged-package-id> --native-ci-run <actual-CI-run-id> \
  --shadow-key /secure/shadow-hmac.key \
  --publishing-bundle /release/exact-final-signed \
  --output /release/GUARD_GA0510.json
```

The gate verifies the independent signature and checks **all** signed evidence files against their real SHA-256, including final installers, machine-specific native signature receipts, six native game receipts, all per-loader real joins, hostile JVM executions, original frame-capture CSV and the HMAC-chained shadow observations. A different published package, stale approval, skipped test, missing OS/CPU, wrong JVM version, mismatched build, unreviewed incident, inconclusive false positive, or insufficient legitimate player-hours makes the command exit nonzero and leaves no success receipt.

`.github/workflows/production-release-candidate.yml` invokes this gate as a **mandatory fail-closed step before publication** when `VERSION=0.51.0`. Configure `guard_0510_evidence_run_id` and `guard_0510_native_ci_run` inputs and external `NL_GUARD_GA0510_REVIEWER_ED25519_PUBLIC_KEY_HEX`, `NL_GUARD_RELEASE_OPERATOR_ID`, `NL_GUARD_SHADOW_HMAC_KEY_HEX` settings. The review artifact name is `launcher-guard-ga0510-<commit>` and contains `evidence/`, `approval.json` and `approval.sig`. Missing settings are a blocker, not an implicit authorization.

The prior general signed-target GA approval, 0.50.0 migration evidence, main CI and existing native delivery checks remain separately required. Passing this Guard-specific gate alone does not waive any unrelated product-wide GA criteria. A Trusted JVM agent has in-process trust, **not** isolation; user-mode sensors cannot guarantee detection of every kernel or privileged-host compromise.

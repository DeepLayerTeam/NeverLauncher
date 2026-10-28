# 0.36.0 verification report — source-level work, NOT a GA certification

Input: user-supplied `NeverLauncher-main(20261028-195111).zip` with VERSION=0.35.14. Scope: Desktop & Operations GA release hardening. Version advanced to 0.36.0.

## Changes actually implemented

- Independent Ed25519 operator-signed GA authorization over six actual platform executable and installer hashes, nine named executable acceptance records per platform, per-check trace SHA-256, exact commit, narrow 7-day validity and full deny-on-omission semantics.
- Real production release pipeline rejects unsigned, stale, failed, simulated, wrong-platform or tampered evidence **before Ed25519 release signing**. It embeds the approval/verified receipt before the release manifest/checksum generation.
- Mandatory Compatibility + Device Trust + Guard CI publish-check for 0.36.0; previous release script merely logged when all three were absent.
- Resumed 0.35.14 native, Desktop, operations, PostgreSQL and owner/Player RC source tests for 0.36.0 without renaming the historical evidence schemas or treating RC as GA.
- Protected `production-release` workflow now requires an externally signed operator approval artifact for the exact commit and target bytes; no self-signed fixture can satisfy the production gate.

## Locally executed

- `python3 -m unittest scripts.ga.test_verified_targets_0360`: 15/15 positive/negative signing, artifact hash and execution-trace tests passed. Keys in tests are temporary fixture keys only.
- `python3 -m unittest discover -s scripts/rc -p 'test_*.py'`: 18/18 RC tests passed.
- `python3 scripts/version/manage.py check`: passed at 0.36.0.
- `bash -n scripts/release/build-release.sh`: passed.
- Production workflow YAML parsed; no GitHub execution has been observed.
- Direct invocation of GA verifier without operator key: exit 3 / refused.

## Not executed; release decision

No approved evidence or signed installers were provided in the input. Actual Rust/Tauri production compilation, real Minecraft/ServerBridge/official authentication, complete Windows/Linux/macOS native platform matrix, protected PostgreSQL/Redis/S3 operations, full DR, stable owner publish/rollback, Authenticode/notarization and 1/10 GiB performance **were not executed in this environment**. No actual RPO/RTO or performance advantage was measured.

**GA decision: BLOCKED.** Source changes and their local security regressions are deliverable, but this is not yet an independently certified 0.36.0 production artifact. All six selected release targets must be verified; partial releases are deliberately not permitted by the existing six-target bundle assembler.

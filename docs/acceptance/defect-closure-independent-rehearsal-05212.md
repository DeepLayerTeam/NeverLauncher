# 0.52.12 — Defect Closure & Independent Rehearsal

## What is actually executed

`defect_rehearsal_05212.py` is an executable final-byte release-candidate freeze and independent-review tool, not an issue table, passive manifest validator, or GA-authorisation endpoint. Every successful review does all of the following on the approved **exact** source commit:

1. Requires the checkout HEAD to equal the operator-approved 40-character commit, the Git tree to remain unchanged, and the worktree to be clean, including untracked files. This is an existing native checkout with `.git`, not a source ZIP.
2. Opens **six complete downloaded final packages** (Windows/Linux/macOS x64/ARM64), including Linux detached signatures, and verifies exact byte size and SHA-256 against a **separately pinned** production distribution index. The index is scoped to project, version and source commit. It refuses missing/extra artifacts and unsafe links. Native Authenticode/GPG/notarization and real install/launch are verified by the existing 0.52.2 **raw** native installer replay, not inferred from hash matches.
3. Checks a **separately signed, complete issue-tracker export** for the exact source commit. Every P0/P1 must be `closed` and identify a mandatory actually executed regression suite, not an arbitrary command. Issue-list authenticity and completeness ultimately depend on the independent issue-export signer and their access to the authoritative tracker. An unsigned list or a release-signing key reused for issue review fails.
4. Executes the real version check and a fixed collection of source regressions (compatibility, six-platform packages, independent build, Guard/ServerBridge, HA/DR and 0.52.12 tamper tests). Writes and fsyncs bounded original logs; re-execution on the verifier requires an unchanged test inventory and validates original log hashes.
5. Calls the production **full** `sweep_05211.verify_full()` twice on the original, current-version live evidence. This replays all 280 Minecraft required outputs and original client/server logs, all six OS-signed final installers, six native game runs, separately signed two-builder reproducibility results, five one-hour real gameplay soaks and the one-hour HTTPS load ledger. Neither `status: passed` nor a unit-test fixture is sufficient. It must return the original `OBSERVED_NOT_INDEPENDENT_GA` result twice, identically.
6. Enforces the fixed Minecraft soak session-copy equality check even when Python runs with optimisations (`-O`); rejects a replaced copied session instead of accepting an omitted `assert`.
7. Rechecks the frozen Git tree, all six package bytes and the issue export **after** the run. The independent reviewer signs the resulting observation with a dedicated Ed25519 key; the separate verifier opens the same raw evidence, re-runs the regressions and full sweep, and validates the signature and immutable log digests.

The three stages `freeze`, `rehearse`, `verify` are designed for different protected runners; the final verifier must not share release or issue-tracker signing keys. The workflow is `.github/workflows/defect-closure-rehearsal-05212.yml` with independently controlled environments `release-candidate-freeze`, `independent-release-rehearsal`, `independent-release-verification` and machine labels `release-freeze`, `independent-review`, `independent-verifier`. Its `workflow_dispatch` requires the *out-of-band* approved source commit, project and index SHA-256. CI pull requests run negative and regression tests, **not** production freeze/GA.

## Independent inputs (never commit private keys or accounts)

- Release freeze host: absolute `$LAUNCHER_05212_FREEZE_INBOX/packages` holding exactly six final `.exe`/`.deb`/`.pkg` and two Linux `.deb.asc`, plus `source-index.json`. The index hash comes from the protected workflow input, not the index itself. `LAUNCHER_05212_FREEZE_SIGN_KEY_PATH` is a 0600 Ed25519 PEM **outside** checkout.
- Independent review host: `$LAUNCHER_05212_REHEARSAL_INBOX` has an independently fetched copy of the same final package files/index, an actual signed `issues.json`/`issues.sig` export, and `full-sweep-paths.json` pointing to original E2E/soak/rebuild inputs already transferred from the verified CI and native labs. Original logs must be present and regular files. The reviewer's private key is a separate outside-checkout, mode 0600 PEM.
- Independent verification host: `$LAUNCHER_05212_VERIFY_INBOX` holds its **own** authentic, independently obtained source packages/index, signed issue export and original evidence. It must not silently trust a copy of a receipt from the release builder.
- In each protected environment, the public keys and separate SPKI SHA-256 pins must be configured from an external trusted channel. Release, issue authority and reviewer pins are **different**. The signing keys must not be uploaded as workflow artifacts. Private authentication/Minecraft credentials must stay in the physical lab, never in a public report.

### Signed issue export format

The independent tracker-export signer signs the canonical sorted JSON (no whitespace dependence) using Ed25519 on the exact bytes `b'neverlauncher.defect-closure.0.52.12\\x00' + canonical_json`. This is **not** a way to create or close tickets in the tracker:

```json
{
  "schema": "neverlauncher.defect-closure-export/0.52.12",
  "version": "0.52.12",
  "commit": "<40-character approved git SHA>",
  "scope": "all-open-release-defects",
  "issues": [
    {
      "id": "NL-100",
      "severity": "P1",
      "status": "closed",
      "regression": "scripts.acceptance.test_sweep_05211"
    }
  ]
}
```

This is format guidance, **not** proof that the example issue exists or has been closed. The record must be an authentic complete export of the real tracker for the commit. A manufactured empty export defeats the process regardless of cryptography: restrict the issue-export key to an independently audited tracker integration.

### Full original evidence configuration

`full-sweep-paths.json` is a JSON object with **exactly** these keys (all paths absolute; no extra fields):

- Original evidence paths: `compat_results`, `native_results`, `source_index`, `native_review`, `native_key`, `native_game_results`, `repro_a_report`, `repro_b_report`, `repro_a_sig`, `repro_b_sig`, `repro_a_key`, `repro_b_key`, `repro_a_dir`, `repro_b_dir`, `game_soaks`, `http_soak`, `soak_key`.
- String observations: `index_sha`, `project`, `native_run_id`, `native_key_pin`, `native_reviewer`, `native_game_run_id`, `package_id`, `repro_run_id`, `repro_a_pin`, `repro_b_pin`, `soak_run_id`, `soak_key_pin`, `compat_run_id`.
- Positive integer observations: `compat_attempt`, `native_attempt`, `repro_attempt`, `soak_attempt`.

`index_sha` must equal the out-of-band pinned release index SHA-256, `project` the frozen distribution project, and every underlying receipt must itself match the approved commit and exact version. The JSON file is **only a way to point the replayer at original evidence**, not a substitute for that evidence.

### Invocations

The CI workflow invokes the concrete commands with all required arguments. For manual review:

```sh
python3 scripts/release/defect_rehearsal_05212.py --help
python3 scripts/release/defect_rehearsal_05212.py freeze --help
python3 scripts/release/defect_rehearsal_05212.py rehearse --help
python3 scripts/release/defect_rehearsal_05212.py verify --help
```

Missing source checkout, missing/altered final bytes, untrusted keys, an open P0/P1, uncompleted one-hour tests, incomplete Minecraft/native runs, disagreement between two replays or a changed regression log **blocks** rehearsal and produces no signed PASS. Normal CI locally checks code and negative tests but **cannot issue** an external acceptance receipt without real input assets/hardware.

## Limits of the actual 0.52.12 claim

The successful status is deliberately `REHEARSED_NOT_GA`; it confirms independent replay of the supported original suites, not every possible real user task. E2E-01–18, all ServerBridge/Guard/Device Trust physical combinations, migration of three real Gravit projects and physical multi-host incidents retain their own existing dedicated 0.52.3–0.52.10 live gates. If their results are unavailable, the 0.53.0 full acceptance remains **BLOCKED**. Do **not** reclassify missing `required` targets as optional, issue GA from signed self-reports, or promote artifacts rebuilt after frozen-candidate acceptance.

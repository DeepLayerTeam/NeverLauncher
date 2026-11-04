# 0.52.11 — Full Compatibility Sweep & Soak

These commands execute production clients and servers. They are **not** a foundation-only / manifest-only acceptance. Unit tests cannot establish GA. Keep the source commit fixed for all five underlying runs; each run has its own actual GitHub run ID and attempt, which the replay checks.

## Automatic paths

1. `.github/workflows/compatibility.yml` builds and executes the 280 mandatory Minecraft combinations, uploading the actual game and server logs. `sweep_05211.py minecraft` is a mandatory fail-closed replay in the CI aggregator. The 12 optional cases are recorded but never used as a substitute for required cases.
2. `.github/workflows/native-final-packages-0522.yml` downloads six externally SHA-pinned signed installers, validates the platform signing chain, system-installs, provisions and verifies. Its independent reviewer signature must be verified again by the full sweep.
3. `.github/workflows/native-game-acceptance-04314.yml` runs the actual six-platform GUI game execution and adversarial checks. The full sweep replays the raw outputs. These are separate from installer checks.
4. `.github/workflows/reproducibility-current-05211.yml` performs two **separate** native builder sets (Windows x64/ARM64, Linux x64/ARM64, macOS x64/ARM64), signs both complete source/lockfile/byte reports with different keys, and independently re-hashes all 12 unsigned archives and their members. The original 0.47.0 workflow remains historical; do not use its 0.47.0 receipt for this release.
5. `.github/workflows/real-soak-05211.yml` runs five live game/loader anchors on the dedicated disposable gaming lab, plus an hour of concurrent HTTPS load on a disposable HA lab. The independent-review job (separate protected reviewer host) recomputes results and signs raw evidence. Every live test is blocked if the dedicated machines, keys, server ZIPs or TLS trust are missing.

## Live soak conditions

- Game targets: Vanilla 26.3, Fabric 26.3, Quilt 26.3, Forge 26.3, NeoForge 26.2 on Linux x64 with Java 25. At least 8 successful sessions **per loader** and at least 3600 seconds elapsed. Every session must satisfy the existing actual Mojang-client/Java/loader/live server join/RCON/ticks/clean stop verifier. Target selection must match `compatibility/targets.json` exactly. Each individual log and result SHA must still match after copying to a new acceptance directory.
- HTTPS: an operator-approved real HTTPS health/read endpoint of a live Standard/HA deployment with a valid TLS chain, 8 concurrent clients, at least 10,000 successful HTTP 200 requests spanning one hour, zero failed requests and p95 ≤ 1500 ms. The verifier independently recalculates p95, byte count and duration from the hash-bound `requests.bin` samples. Adjust the target p95 only via an explicit product decision and corresponding tests, not by editing the receipt.
- If the Minecraft runner hangs, its entire process group is killed. Its blocked result is not counted. A dedicated disposable checkout and `LAUNCHER_ACCEPTANCE_DISPOSABLE=1` are required; never run this test against an owner's production world or unbacked user data.
- The reviewer private Ed25519 key lives **outside** the checkout and must be protected by an independently approved environment. The public SPKI SHA-256 is pinned separately. A signed report is still **not** production GA by itself.

## Full independent replay

The final operator runs `python3 scripts/acceptance/sweep_05211.py full` with **all** of these paths/arguments (none optional):

- `--commit`, `--compat-results`, `--compat-run-id`, `--compat-attempt` for raw output of 280 successful CI executions;
- `--native-results`, `--source-index`, `--index-sha`, `--project`, `--native-run-id`, `--native-attempt`, `--native-review`, `--native-key`, `--native-key-pin`, `--native-reviewer` for the six final installer receipts, pinned public index, and independent reviewer signature;
- `--native-game-results`, `--package-id`, `--native-game-run-id` for the six actual GUI game outputs;
- `--repro-a-report`, `--repro-a-sig`, `--repro-a-key`, `--repro-a-pin`, `--repro-a-dir` and the corresponding `--repro-b-*`, plus `--repro-run-id`, `--repro-attempt` for both source-identical independently signed native build outputs;
- `--game-soaks` containing exactly the five named loader directories (and optionally `https`), `--http-soak` pointing to the signed HTTPS evidence, `--soak-key`, `--soak-key-pin`, `--soak-run-id`, `--soak-attempt`;
- `--output /absolute/fresh/path/sweep.json` to write an immutable replay result.

All native and independent-build inputs must come from the **same source commit and product version**, but different workflows can and will have different run IDs. No manual `PASS`, absent source log, stale signature or reused native runner identity is accepted. The aggregate returns `OBSERVED_NOT_INDEPENDENT_GA`; final 0.53.0 GA still requires a distinct operator-signed final-byte release gate.

## Locally executable regressions

```sh
PYTHONPATH=scripts/release:scripts/acceptance python3 -m unittest -v \
  scripts/release/test_reproducible_0470.py \
  scripts/release/test_unsigned_package_0470.py \
  scripts/release/test_independent_current_05211.py \
  scripts/acceptance/test_soak_05211.py \
  scripts/acceptance/test_sweep_05211.py
python3 scripts/version/manage.py check
```

This work does not itself constitute proof of the six external installation/minecraft runs, 280 live targets, multi-hour soak, or independently reproduced release. Missing external evidence **must** keep 0.52.11 real acceptance BLOCKED.

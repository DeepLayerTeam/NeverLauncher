# NeverLauncher 0.35.1 local acceptance evidence (28 October 2026)

**Release claim:** The source contains an executable G/M user journey audit and an opt-in real Backend owner/player HTTP acceptance runner. This is not a Minecraft/runtime GA certificate.

## Verified locally in the provided checkout

- `python3 scripts/acceptance/ux_0351.py audit`: **PASS**; exactly 35 G and 19 M IDs; every reference is a present source/test file; all UX01–UX12 have explicit G/M coverage; all 54 remain `not-run` for real target acceptance.
- `python3 scripts/acceptance/test_ux_0351.py -q`: **7 tests passed**. Negative coverage includes invalid IDs, bogus `verified` status, path traversal, missing executable and unsafe status promotion.
- `python3 scripts/acceptance/ux_0351.py run --ids M04,M07 --report /mnt/data/nl-0351-run-local.json`: **2/2 passed**; Node tests of actual prebuilt asset verification, deferred startup prewarming and Desktop experience domain behavior.
- `node --test apps/desktop/tests/component_selection_0247.test.mjs` after compiling `component_selection_0247.ts` with TypeScript: **3 tests passed**; dependency cascades, required component refusal and malformed choice rejection.
- `python3 scripts/acceptance/test_owner_player_api_0351.py -q`: **4 tests passed**, including non-JSON responses, oversized bodies, unexpected HTTP rejection and invalid route prefixes. Tests use a fake HTTP listener only to test the harness rejection path, not to certify the product.
- `python3 scripts/version/manage.py check`: **PASS**, including Cargo/Tauri/Admin/Desktop metadata and canonical OpenAPI version.
- `bash -n scripts/acceptance/run_owner_player_0351.sh`: **PASS**.

## Not certified locally

- `Go 1.23.2` is below `services/api/go.mod` required `go 1.27.3`. The real disposable Backend acceptance **was not executed locally**; source workflow must run it with a suitable Go toolchain.
- A mixed Go+Node G08/G09 local run reported blocked/failed with Go toolchain mismatch and untranspiled TS until the separate TypeScript build was performed. This does not invalidate the successful separate optional-mod Node tests and is not counted as a full G08/G09 acceptance pass.
- Windows/macOS/Linux native Desktop installer, official Microsoft entitlement, ServerBridge live join, staged Minecraft E2E, protected PostgreSQL stable commit and live GA attestor were **not run**. `docs/reports/ga-readiness-0350.md` remains applicable.
- CI workflow is authored but no CI execution result from this checkout is claimed.

- `python3 scripts/smoke/offline/repository-policy.py`: **FAILED**. Comparison with the unmodified supplied 0.35.0 archive showed the exact same pre-existing failures: missing mirrored SQL migration files, stale 0.31.x UI version literals, missing historic attestation path token, compose volume ownership and embedded template drift. The 0.35.1 patch does not claim repository-wide policy compliance.

## Gate conclusion

0.35.1 source-level acceptance harness is available and its local runner regressions passed. There is **no evidence** to label all 54 G/M user journeys verified, or to claim a completed owner publish/rollback workflow or a playable clean-machine Desktop. Preserve existing fail-closed stable publication rules.

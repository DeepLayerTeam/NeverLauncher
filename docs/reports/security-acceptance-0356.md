# 0.35.6 local acceptance evidence (not GA)

| Check | Local result | Evidence |
|---|---|---|
| Desktop extension validation, scope, stale HTML, RPC size, bridge attestation | PASS, 4 tests | `npm run test:extension-security` |
| Production/dev CSP, main capabilities, native path/link guard invariant | PASS, 3 tests | `node --test apps/desktop/tests/security_policy_0356.test.mjs` |
| Changed TS/TSX syntactic transpilation | PASS | TypeScript `transpileModule` diagnostics |
| Prestarter full Go suite including signed branding/bootstrap | PASS | `cd prestarter && go test ./... -count=1` |
| API RPC revocation and generation integration test | NOT RUN locally | Go 1.23.2 available; services/api requires Go >=1.27.3; CI has test |
| Native Rust HTTPS validation and compile | NOT RUN locally | Rust/Cargo unavailable; CI has tests |
| React production bundle | NOT VERIFIED locally | Missing installed project npm dependencies |
| Real WebView CSP + iframe integration across Windows/Linux/macOS | NOT RUN | Requires native target/UI test rigs |
| Embedded extension inline JS under inherited parent CSP | KNOWN BLOCKER | Current `srcDoc` scheme inherits main CSP; see release notes |
| Real Minecraft/Desktop release certification | NOT RUN | No GA claim |

The tests above exercise real validation logic and the Backend permission check is implemented in the existing RPC handler. The local PASS records do not certify the entire application as production-ready. Stable release gates and real runtime certification are unchanged.

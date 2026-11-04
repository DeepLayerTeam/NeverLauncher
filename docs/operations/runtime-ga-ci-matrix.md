# Launcher 0.35.0 — CI and independent runtime matrix

| Check | Runner | Trust | Required for 0.35.0 GA |
|---|---|---|---|
| Python V02–V12, synthetic negative assertions | `validation-attestor-0345.yml` | CI, untrusted for positive Minecraft runtime | Yes, regression only |
| `TestGAStableSnapshotImmutablePostgres0350`, V11, V12 and adversarial Go suites | `runtime-acceptance-0350.yml` PostgreSQL 17 | Test DB | Yes, prevents SQL bypass |
| Actual staged download and client/server with graphical Minecraft | `staged-package-runtime-0342.yml` | Observational, **not** attested | Yes, supporting observation |
| Windows/Linux/macOS headless and GUI across declared architectures | `native-runtime-v10-03410.yml` | Observational unless independently attested | For all claimed targets |
| Immutable staged execution in pinned rootless OCI image, independent signing | External attestation service | Trusted attestation domain | One independent result **per target** |
| Real official Microsoft/Xbox/XSTS/Minecraft and custom join/hasJoined policy | Protected real accounts/server | Trusted only if independently attested | For applicable auth targets |
| Update, damaged cache, repair, interruption, Java replacement, rollback | Live previous + current release | Trusted only if independently attested | All required lifecycle targets |
| Live Backend required coverage / source SHA / matrix digest | `runtime-acceptance-0350.yml` | Read-only preflight | Yes; repeat at signing |
| Durable stable publish & SQL head guard | Backend / PostgreSQL 17 | Last authoritative gate | Required before opening stable |

The target list is generated from the actual signed component catalog and explicit required target policy. Every published preset and reachable condition branch must be represented; compatible additional pairs are a bounded sample and all untested combinations must remain clearly marked as unverified. Headless cannot substitute for graphical gameplay. A skipped, unavailable, failed or inconclusive mandatory target blocks stable.

Set protected GitHub environment `runtime-validation-ga` with `NL_GA_BACKEND_URL` (variable, HTTPS origin) and `NL_GA_OPERATOR_TOKEN` (read-only API token, secret). Production release environment must also provide these and `NL_GA_PACKAGE_ID` from the dispatch input. `runtime-acceptance-0350.yml` checks all target evidence against exactly `github.sha`, while `scripts/release/build-release.sh` rechecks at signing. A missing environment/secret is an intentional blocking condition, never a fallback to CI-generated mock data.

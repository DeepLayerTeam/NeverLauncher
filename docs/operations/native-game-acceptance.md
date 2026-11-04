# 0.43.14 — native Minecraft gameplay acceptance

This is a **real-execution gate**, not a declaration of platform support.

Run `.github/workflows/native-game-acceptance-04314.yml` for one immutable,
properly signed staging package. It dispatches the existing GUI-capable staged
runner on six **dedicated native hosts**: Windows, Linux and macOS, each on
x64 and ARM64. Each host must have a physical/logged-in GUI session with
rendering and input permissions, the required Java and signing configuration,
a real matching Minecraft server/ServerBridge distribution, a registered
external authentication provider and dedicated test accounts.

A successful run requires the full existing sequence: exact staged-byte
materialization, selected loader and native Java, Minecraft GUI and JVM startup,
provider authentication including negative device/Guard checks, signed matching
server, player join and server-confirmed movement with changing rendered frames,
followed by real transactional update/recovery/rollback. After successful
Minecraft play, the actual production Runtime must reject a modified signed
manifest and the production Go CLI must reject a corrupted *required* client
file. The isolated test copy is then restored and verified again. Errors,
timeouts, missing toolchains, missing GUI, SKIP, mismatched architecture or
unsuccessful rejection produce a **blocked** run. x64 emulation is not ARM64.

`run_native_validation_03410.py` checks the real host identity and verifies
the positive/negative reports. The `adversarial-gameplay-04314.json` result is
SHA-256-bound into the gameplay proof. Independent host-side validation checks
this result and the exact restored package bytes; the Backend refuses signed
0.43.14+ gameplay evidence without the new artifact hash. These observations
are **not themselves signatures or approval to publish**. Final GA still
requires separately approved, current, independently signed evidence for the
exact release bytes from the trusted platform verification process.

Linux-only validation-attestor 0345 remains Linux/amd64; it must **not** be
represented as a six-platform attestor. The six-target GUI workflow is a native
observational acceptance, not a substitute for the independent release
security-capability matrix and platform signing. If a platform host or trusted
attestor is missing, that target is unverified and release certification stays
blocked. This release does not claim these tests have already run.

Unit regression commands (not a substitute for Minecraft E2E):

```sh
python3 tools/validation-attestor/test_attestor.py
python3 e2e/scripts/test_staged_negative_04314.py
python3 e2e/scripts/test_run_staged_package_0342.py
python3 scripts/ga/test_security_capabilities_0431.py
```

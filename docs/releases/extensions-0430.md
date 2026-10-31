# Launcher 0.43.0 — Java extensions and Gravit source-port release

This release introduces executable, signed example `.nlext` packages and an enforced six-target JVM certification in the production workflow. It **does not** claim complete binary compatibility with upstream GravitLauncher modules. `module-parity-04211.json` retains 18 **partial** functional analogues and the intentionally **blocked** UnsafeCommandPack.

## Production prerequisites

1. Configure protected repository secrets `NL_EXTENSION_PUBLISHER_PRIVATE_KEY_PEM` and `NL_EXTENSION_PUBLISHER_PUBLIC_KEY_PEM`, holding an approved Ed25519 private/public PEM pair. **Do not** reuse the release-signing key or commit private key material. Trust the public key explicitly through the Extensions publisher trust mechanism before installing shipped examples.
2. Make all six target runners available: Windows/Linux/macOS on x64/ARM64. The `extension-real-acceptance-04212.yml` reusable workflow builds Java 21, compiles native CLI, executes four real JVM/CLI scenarios and the pinned 19-module auditor, tests signed packages against wrong keys and tampering, and runs Backend Supervisor race tests using the toolchain declared in `services/api/go.mod`.
3. The workflow must emit six same-run raw JSON results and `extension-acceptance-certificate.json`. `production-release-candidate.yml` requires the reusable workflow to succeed and downloads the **same run** artifact. No cross-run or old-version result is accepted.
4. `build-release.sh` uses the dedicated publisher identity to sign example Java Host and Gravit source-port `.nlext`. It cryptographically verifies each with the pinned publisher public key. The new certification also compares all six reports against the recomputed certificate, checks the modules against current source/test files and binds the final package byte hashes.
5. Every published release must contain the two signed `.nlext` files, `EXTENSION_PUBLISHER_PUBLIC_KEY_0430.pem`, `EXTENSION_RELEASE_CERTIFICATION_0430.json` and `EXTENSION_ACCEPTANCE_EVIDENCE_0430.zip` in the signed root BOM and `SHA256SUMS`. Omission blocks release build/verification.

## Example packages

- `launcher-example-java-host.nlext`: authentic Java Host process and CLI contribution example.
- `launcher-example-gravit-port.nlext`: explicitly source-ported module using Java SDK events, durable storage and CLI. This does **not** run unmodified third-party Gravit JARs.

The example manifests remain independently versioned as `0.1.0`; this is independent of Launcher `VERSION=0.43.0` and the Java SDK API `1.0`.

## Evidence semantics and limitations

The aggregate JSON is **CI-run-bound evidence**, not a separately operator-signed six-platform attestation. Its trust comes from protected GitHub Actions execution, native runner availability, same-run artifact retrieval and final signed release manifest. The bundle's example package signer also does not establish general Java process sandboxing. Java Host remains a trusted process; Guard is not an OS sandbox for Java extensions.

A developer workstation can run `python3 e2e/extensions/accept_04212.py --target linux-x64 --cli /path/to/nl --evidence /tmp/linux-x64.json` after building the examples; this yields only a *local single-target* result. It must not be reused to fabricate or populate the other five target reports. An absent required live target blocks production release.

The 19-module inventory documents exact features and limitations, not 19 complete upstream replacements. Full equivalence requires live service/game-specific tests for each module, independent of having passed the generic Java Host E2E.

## Outstanding upstream/repository prerequisites

Before claiming a production GA release, resolve existing stale `cli/cmd/launcher`, `runtime/runtime`, missing historical Guard test paths, and run the full protected CI and ServerBridge/Minecraft production suite on exact final packages. Unit tests, a local Linux x64 JVM run and workflow YAML are not substitutes for those results.

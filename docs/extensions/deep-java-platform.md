# Deep Java Platform 0.49.0 — source patch and acceptance status

## Executable changes

- Java callback entrypoint now refuses mutations before RUNNING and after STOPPING; a STOPPING callback health response is non-responsive. Shutdown cancels outstanding callbacks, refuses new submissions and prevents re-use of the old callback token when an instance restarts.
- `RuntimeCallbacks0490Tests` exercises real loopback TCP/HTTP, a blocking Java handler, concurrent shutdown, token rotation, and new process state; these are not mocks of the Java callback implementation.
- `scripts/java/deep_java_e2e_0490.py` compiles three different **existing** Java extension implementations against a published binary SDK JAR only. It runs separate real JVM subprocesses for (1) Admin/Desktop/CLI actions and persisted settings, (2) Content SPI asset/texture/metadata/prepare/delivery plus SHA-256, and (3) Java SPI with a pinned nested library, live provider selection and CLI. The Host in these particular integration tests is a local Python test double, **not** the installed Go service.
- The 0.48.12 Java external-consumer workflow previously published the Maven SDK into `$RUNNER_TEMP` while Maven, Gradle and its integrity tests looked for `dist/java-sdk/maven`. This is corrected; the example build definitions accept an explicit SDK version so the same example exercises 0.49.0 rather than silently compiling against an older artifact.

## Verification and scope of evidence

A local OpenJDK 21 acceptance run covers independent public SDK publication, three JVM subprocess extensions, callbacks, CLI, heartbeat, shutdown, wrong-token denial and version metadata. The 0.49.0 CI workflow repeats these checks using Java 17 and 21. Merely adding workflow jobs does **not** prove they have run.

## Blocked GA requirements

**The source version number is 0.49.0, but full production GA certification is NOT established.** The following must be completed independently on a real deployment before signing a GA release:

1. Signed `.nlext` installation of several third-party extensions from independently built packages, real Go Host Broker authorization and audit, privileges revoked during outstanding operations, and safe restart.
2. PostgreSQL state migration through an actual interrupted upgrade, rollback, reinstallation and crash recovery; compare before/after data, not just manifests.
3. Linux/Windows/macOS runtime and native sandbox enforcement including direct JVM network and filesystem denial, on required x64/arm64 targets; unsupported strict isolation must remain fail-closed.
4. Real Minecraft client/ServerBridge integration, genuine signed production packages and all inherited 0.47.0/0.48.0 release and reproducibility checks.
5. Independent CI on Java 17/21, Go Backend integration/race suites, external Maven/Gradle builds and externally signed release evidence tied to the exact source commit and artifact digests.

No production GA attestation, signature, independent CI result, installed Backend result or native OS sandbox acceptance is included with this patch. Do not use its local test report as a production acceptance certificate.

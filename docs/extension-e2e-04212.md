# Extensions 0.42.12: executable acceptance

The acceptance runner executes **four real Java processes/examples** on the target OS: Java Host, Runtime EventBus/storage/CLI, Lifecycle, and a Gravit source-port module. It checks authenticated Host Protocol, Java callbacks, events, restart behavior, error cases, actual JARs, CLI packaging, Ed25519 signatures and rejection of modified JAR payloads and wrong keys.

Run from a fresh checkout with Java 21, Python 3.12+, OpenSSL and the project's Go toolchain:

```sh
sh sdk/java/core/build.sh test
sh sdk/java/gravit-compat/build.sh test
sh examples/extensions/java-host/build.sh
sh examples/extensions/java-runtime/build.sh
sh examples/extensions/java-lifecycle/build.sh
sh examples/extensions/gravit-compat/build.sh
(cd cli && go build -o ../nl ./cmd/launcher)
python3 e2e/extensions/accept_04212.py --target linux-x64 --cli ./nl --evidence evidence/linux-x64.json
```

On Windows use the native `.exe` and Git Bash `sh`; pass `windows-x64`/`windows-arm64` as appropriate. Runner checks the **actual host** and JVM architecture; cross-compilation, emulation and fabricated target labels do not certify native execution. CI runs this on Linux, Windows and macOS x64 and arm64; an unavailable runner **blocks** the aggregate rather than becoming a pass. Run the Go supervisor suite separately using the project's Backend toolchain and built Java Host JAR:

```sh
(cd services/api && LAUNCHER_TEST_JAVA_HOST_JAR="$(cd ../.. && pwd)/examples/extensions/java-host/build/package/backend/java-host.jar" go test -race -count=1 ./internal/extensionhost)
```

Only a successful real-runner invocation may write `status: pass`. Evidence includes exact JAR hashes, CLI hash, source commit (on CI), OS architecture and JVM info. The aggregate requires all six target records for the exact CI commit and the independent Go Supervisor job to succeed. `e2e/extensions/aggregate_04212.py` refuses missing/failed/stale/wrong-architecture results, unverified signatures and missing negative cases.

## Interpretation

This suite validates extension delivery and protocol behavior; **it does not certify** all 19 Gravit feature replacements, launch a Minecraft client, demonstrate a complete PostgreSQL/HA install/update/rollback cycle, validate Guard native sandboxes across the OS matrix, or certify the final production packages. Guard and Java Extension Host have distinct trust boundaries: the Java host is a separate **trusted** JVM process, not an OS sandbox for untrusted JARs. No public production release or verified status for the 19 Gravit modules is implied by this suite.

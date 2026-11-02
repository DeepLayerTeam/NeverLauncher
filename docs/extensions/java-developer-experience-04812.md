# NeverLauncher 0.48.12 — Java Developer Experience & E2E

## Delivered SDK publication (actual built artifacts)

`dist/java-sdk/maven/ru/launcher/` contains the published **0.48.12** Java 17 ABI artifacts:

| Maven artifact | Contents | Dependency |
|---|---|---|
| `ru.launcher:launcher-java-sdk-core:0.48.12` | Extension, Host, SPI, events, identity, content, UI, lifecycle, JSON and broker client | JDK 17+ |
| `ru.launcher:launcher-gravit-compat:0.48.12` | Limited, source-portable Gravit compatibility adapter | `launcher-java-sdk-core` |
| `ru.launcher:neverlauncher-api-sdk:0.48.12` | Working HTTP API client and 452-operation registry | `launcher-java-sdk-core` |

Each artifact has a binary JAR, sources JAR, generated Javadoc JAR and real Maven POM; each file has SHA-256 and SHA-512 sidecars. Artifacts are built with `javac --release 17`; **these are unsigned local publication artifacts**, not Maven Central releases or a production signature. They are shipped so developers can compile without access to NeverLauncher internal source tree.

Reproduce the local publication from source using JDK 17/21 and Python 3.12:

```sh
sh sdk/java/core/build.sh test
sh sdk/java/gravit-compat/build.sh test
sh sdk/java/http-client/build.sh test
python3 scripts/ga/java_sdk_ga_0310.py --skip-build --output /tmp/java-sdk-04812
python3 scripts/java/compare_sdk_repos_04812.py dist/java-sdk/maven /tmp/java-sdk-04812/maven
```

The final comparison is **byte-for-byte** and assumes the same effective compiler/Javadoc versions for the checked-in publication and the local rebuild. Cross-JDK source compatibility is tested separately; differing Javadoc output across toolchain versions does not imply API incompatibility.

## Independent consumer (Maven + Gradle)

The complete sample is `examples/extensions/java-developer-04812/`. Maven and Gradle **both** resolve SDK coordinates from the packaged local Maven repository, not source-tree `build/classes`. The sample implements Java extension lifecycle, Admin/Desktop action handlers, validated persisted settings and a CLI `status` command.

```sh
mvn -B -ntp -f examples/extensions/java-developer-04812/pom.xml package
gradle --no-daemon -p examples/extensions/java-developer-04812 classes
```

Maven/Gradle themselves (and their standard compiler plugins) must be installed or accessible in the build environment. The local publication and the JVM integration harness need only JDK and Python, **not** Maven/Gradle or network access.

Build a deployable **unsigned** extension directory from the *published* SDK, not local SDK class directories:

```sh
python3 scripts/java/build_developer_package_04812.py --output /tmp/java-developer-package
python3 scripts/java/developer_e2e_04812.py --report /tmp/java-developer-e2e.json
python3 scripts/java/test_developer_e2e_04812.py
```

The generated directory contains `launcher-extension.json`, `backend/workspace.jar`, `cli/workspace.jar`, `admin/index.html` and `desktop/index.html`. Use the existing `nl extension pack` with a real publisher's Ed25519 signing key and the normal trusted installation workflow; this tool deliberately does not sign, install or grant capabilities.

## Independent functional evidence and adversarial checks

The E2E harness compiles **only** the sample source against the Maven **binary** SDK. It reads its own signed-package-compatible manifest and starts a real `java -jar` process against an authenticated, loopback-only Python HTTP Host implementation. Tests cover:

- Real JVM hello/ready/heartbeat/lifecycle and process termination;
- Authenticated Admin and Desktop `ui.action.invoke` callback execution;
- `ui.settings.get/put` persistence through the simulated Host broker and JSON Schema rejection;
- Short-lived CLI `status` execution with a separate target;
- Refusal of unknown unsigned actions and incorrect callback bearer tokens;
- Maven POM dependencies and checksums, Java 17 `.class` bytecode limits, duplicate/unsafe entries;
- Tampered JAR, missing sources JAR, invalid SHA-512 and corrupt dependency POM failures;
- Determinism: two separately staged Maven repositories compared byte-for-byte.

The Python Host is a test double for the real Go Broker: **the test confirms Java-to-Host protocol behavior, not end-to-end Go persistence, installed signatures, production RBAC or Minecraft sessions.** The Go 1.27.3 integration suite and release certification remain separate blockers.

## Compatibility matrix and evidence interpretation

| OS | Java 17 | Java 21 | Evidence |
|---|---|---|---|
| Linux x64 | CI required | **Locally tested** | Published SDK, real JVM E2E, Core/HTTP/Gravit tests on OpenJDK 21 |
| Windows x64 | CI required | CI required | GitHub Actions matrix using Temurin |
| macOS ARM64 / x64 runner | CI required | CI required | GitHub Actions matrix using Temurin; actual runner architecture recorded by CI |

Cross-platform job: `.github/workflows/java-developer-experience-04812.yml`. Its six OS/JDK combinations execute SDK tests, publication from built classes, external JDK consumer, negative security tests, Maven and Gradle compilation and upload per-job evidence. An independent Linux job repeats the publication twice and compares its binary output. **Adding CI configuration is not evidence the remote jobs have run**. No Java 17 local runtime, Maven, Gradle, Windows or macOS executable is installed in the local acceptance environment used for the 0.48.12 source patch.

## Security boundaries and GA limitations

All Java code in this example is **trusted for the purpose of the local test**; it runs inside a process with the OS permissions of its launcher. Go Host Broker permissions and the signed package trust chain remain necessary in a real deployment. This release does **not** add OS sandbox enforcement, secure arbitrary third-party JVM bytecode, migrate a live PostgreSQL installation, certify Minecraft integrations or satisfy earlier independent GA gates. In particular the previous 0.48.11 Linux/Windows/macOS sandbox restrictions remain unverified and cannot be substituted by a passing SDK test.

# 0.48.2 — упаковка модулей Java и зависимости

This release adds **runtime JAR dependencies** to the existing signed `.nlext` installation lifecycle. It does not download dependencies, alter the launcher core's classpath, open an alternative install path, or grant extra capabilities to an extension.

## фактические пути установки и запуска

1. Compile third-party dependencies with a pinned version and keep the resulting JAR bytes. Build the Java Extension Host as before, including the SDK classes and the actual extension's class file (compiled against dependencies but **without** embedding them among host classes).
2. Run `python3 scripts/java/package_dependencies_0482.py --host host.jar --output bundled-host.jar --library 'org.example:greeter@1.2.3@>=1.0 <2.0@path/to/greeter.jar'`. Repeat `--library` for additional dependencies. The offline builder copies the host content, embeds each dependency under `META-INF/launcher/libs/`, and generates `META-INF/launcher/libraries.lock` containing the embedded path, group/artifact coordinate, pinned SemVer, SHA-256 digest, and SDK API constraint. It never resolves Maven coordinates or reaches the network.
3. Put `bundled-host.jar` in the usual `backend`/`cli` target location, declare the same path in `launcher-extension.json`, and use the **existing verified publisher signing flow** to create and install a signed `.nlext` package. Never sign just the unbundled input JAR.
4. The existing `extensionlifecycle.Manager.inspectPayload0305` validates the actual extracted host JAR **before activation**. The Go inspector rejects missing/unlocked nested JARs, duplicate class names across host/libs, protected package overrides, unsafe entries, changed SHA-256 digests, forbidden Class-Path/multi-release JARs, unsupported class-file versions, and excessive size. The manager checks each dependency's API compatibility against `manifest.api` and probes a suitable Java runtime (including Java 21 when required by dependency bytecode).
5. `java -jar bundled-host.jar` starts the **same JVM subprocess** used by the existing authenticated supervisor. The SDK checks the lock and actual embedded contents again, extracts dependencies into an owner-only temporary directory, and runs the extension class with an isolated child-first loader. SDK/host/JDK classes continue to come from the parent loader. The extension's symbolic references can resolve bundled dependency bytecode while the launcher's core classpath remains unchanged. The directory and loader are closed on completion.

**Safety boundaries:** the library classloader isolates class visibility, **not malicious Java code**. The separate JVM, resource supervision, package publisher signing, existing broker permission checks, and live trust/revocation checks remain mandatory. This feature does not make untrusted bytecode safe to execute or automatically support arbitrary JAR/plugin formats. Native JNI and resource compatibility are not claimed. SDK API acceptance remains `1.0` or `3.7` as supported by the existing manifest parser. An extension dependency may not replace `java.*`, `ru.launcher.sdk.*`, or other protected classes.

**Conflict rules:** different versions of the same coordinate are rejected; different coordinates exposing the same class file are rejected; an inner JAR exposing a class from the outer host JAR is rejected. This is *per-extension* isolation: separate subprocesses may use different versions of a library without affecting each other. Java extension dependencies are **not** resolved by the existing extension-to-extension `dependencies` list; that remains the installed extension package dependency graph.

**Limits:** at most 64 embedded dependencies, 16 MiB per embedded compressed JAR, 64 MiB total embedded JAR bytes, 4,096 entries per nested JAR and 64 MiB decompressed entries per nested JAR. No external Class-Path, network fetching or multi-release JARs. The Go package inspector's signed-package validation still applies independently.

## воспроизводимая интеграция

```
sh sdk/java/core/build.sh test
sh examples/extensions/java-dependencies/build.sh
javac --release 17 -cp sdk/java/core/build/classes -d sdk/java/core/build/test-classes sdk/java/core/src/test/java/ru/launcher/sdk/core/ModulePackaging0482Tests.java
java -cp sdk/java/core/build/classes:sdk/java/core/build/test-classes ru.launcher.sdk.core.ModulePackaging0482Tests examples/extensions/java-dependencies/build/package/backend/java-dependencies.jar
python3 examples/extensions/java-dependencies/test-runner.py
```

`java-dependencies` is a real Java extension that calls code from `greeter.jar` inside its `Extension.start()`, completes the authenticated Go/JVM Host handshake, signals `ready`, responds to a health RPC, sends heartbeat, and exits on shutdown. Go regressions build real nested ZIP fixtures and validate conflicts, protected SDK namespaces, invalid manifests, invalid locks, SHA digests and Java bytecode detection. CI runs the JVM portion on JDK 17 and 21, Linux and macOS, and Go inspector tests under the repository's pinned Go toolchain.

**GA status:** passing this feature's tests does not certify whole-product 0.48.2 GA. Independently verified PostgreSQL migration, signed installer binaries, historical upgrades and production release gates inherited from 0.48.0 must still pass. No blocked gate is bypassed.

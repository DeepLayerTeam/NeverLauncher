# Extensions: Java SDK, API and Host Protocol — 0.42.1

## Compatibility boundary

Product version `0.42.1` **does not change** Host Protocol `1.0`, Extension API `1.0`, package format `1.0` or manifest schema `2.0`. The Go host still accepts the canonical SDK `1.0` hello and the legacy manifest API `3.7` hello behavior. The wire hello request deliberately has no new mandatory fields, so a Java SDK compiled against 0.42.0 can communicate with the updated host. The updated SDK communicates with the original host for operations it actually advertises; the old 0.42.0 Go host did not advertise `runtime.config.delete` or `runtime.storage.delete` even when the underlying broker supported them.

| Situation | Observable outcome |
| --- | --- |
| SDK 0.42.0 hello, Go Host 0.42.1, matching protocol/API | Accepted, same `1.0` response fields |
| SDK 0.42.1 hello, Go Host 0.42.0, advertised capabilities | Accepted; SDK uses existing response fields |
| SDK requires unavailable capability during `connect(callbackUrl, required)` | `CompatibilityError.code() = HOST_CAPABILITY_UNAVAILABLE` before extension `start()` |
| RPC capability not advertised by the host | `SecurityException` in Java before any broker request |
| Event type absent from host's `events` list | `SecurityException` before subscription request |
| Event protocol not `1.0` when advertised | `CompatibilityError.code() = HOST_EVENT_PROTOCOL_MISMATCH` |
| Incorrect hello protocol/API or identity | HTTP `409`; Go Host supplies a stable `code` field |
| Repeated authenticated hello | HTTP `409` with `HOST_HELLO_ALREADY_COMPLETED`; existing runtime identity not reset |
| Invalid readiness acknowledgement | SDK rejects; supervisor marks a JVM ready only after verified `POST /v1/ready` |

## Executable API

`HostSession.connect()` and `connect(callbackUrl)` remain supported. To require permission before initiating callbacks:

```java
try (HostSession session = HostSession.fromEnvironment(System.getenv(), manifest)) {
    session.connect(callbackUrl, Set.of("runtime.config.get", "runtime.storage.put"));
    // Only a host that advertised these effective capabilities can reach here.
}
```

This is an *opt-in startup check*. An extension can omit a requirement if it implements graceful degradation for that capability. At each actual broker operation, the SDK checks the negotiated capability locally and Go checks effective permissions again; negotiation is **not** a grant and cannot supersede revocation. The Go host now advertises both delete capabilities for effective `storage:write`. The event catalog is checked separately from API permissions.

`HostSession.HostError` retains its existing `status()` method and now exposes `code()`. An older Go host may reply in plaintext, in which case `code()` returns `HOST_HTTP_<status>`. The new Go host emits codes for mismatched protocol/API, process identity, callback restriction and duplicate hello.

The JVM `ExtensionRunner` now loads the extension class without running its static initializer until hello succeeds. Only after agreement does it instantiate the extension and invoke `start()`; `ready()` remains after successful start. This prevents startup code from executing for an incompatible host. JVM code remains trusted with process-user privileges; none of these checks provides an OS sandbox.

## Reproducible checks

```bash
sh sdk/java/core/build.sh test
sh sdk/java/gravit-compat/build.sh test
sh examples/extensions/java-host/build.sh
python3 examples/extensions/java-host/test-runner.py
sh examples/extensions/java-runtime/build.sh
python3 examples/extensions/java-runtime/test-runner.py
python3 -m unittest discover -s scripts/ga -p 'test_accept_network_release_0420.py'
(cd services/api && go test ./internal/extensionhost ./internal/extensioncontract ./internal/extensionjava)
```

The Go command requires the repository's declared Go `1.27.3` toolchain. The CI Java SDK workflow tests JDK 17/21 on Linux, macOS and Windows; local Linux tests alone do not certify those targets.

## Release limitation

**The product-wide 14-target ServerBridge Minecraft/JVM/Proxy release gate remains mandatory in 0.42.1.** The gate now recognizes versions `>=0.42.0`, but checks the version and source commit **exactly** in live proofs and on the final release JARs. It rejects missing or incompatible evidence, including absent Go fault/race logs. Until the four outstanding live target runners and full evidence are supplied, production certification remains blocked; this patch must not be presented as a verified production release.

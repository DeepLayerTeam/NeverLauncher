# NeverLauncher Java SDK Core / Runtime 0.30.3

A **working Java 17+** SDK for the existing NeverExtensions API `1.0` / Manifest `2.0` / local Go Extension Host Protocol `1.0`. The SDK does not introduce another manifest, server API or registry. No Maven dependency download is needed to build its jar.

## Build and run tests

```bash
sh sdk/java/core/build.sh test
# Output: sdk/java/core/build/neverlauncher-java-sdk-core-0.30.3.jar
sh examples/extensions/java-lifecycle/build.sh
python3 examples/extensions/java-lifecycle/test-runner.py  # Linux/macOS, requires Java on PATH
```

The core jar can be included in an extension package as `backend/lib/neverlauncher-java-sdk-core.jar`; all Java classes are compiled with `--release 17`. Cross-platform Java 17/21 CI builds and tests the SDK, and Linux CI launches the example as a real child process.

## Runnable extension

Implement `ru.neverlauncher.sdk.core.Extension` with `start(ExtensionContext)` and `stop(ExtensionContext)` methods. The provided `ExtensionRunner` loads the implementation class, validates its shipped manifest and its host identity, performs a real authenticated `POST /v1/hello`, maintains `POST /v1/heartbeat` and executes lifecycle methods on managed executor threads. Exit when the host becomes unreachable or on process shutdown.

A Linux/macOS backend target is an executable launcher script (see `examples/extensions/java-lifecycle/backend/bin/java-lifecycle`). The existing Go supervisor launches it with the active package payload directory as working directory, injecting the `NEVERLAUNCHER_EXTENSION_*` environment variables. The extension process **must not be launched as a general network-facing service**; the SDK accepts only the loopback host origin. `ExtensionRunner` explicitly rejects manifest hooks at this stage: event delivery/subscriptions belong to 0.30.3.

## Packaging with existing NeverExtensions CLI

```bash
sh examples/extensions/java-lifecycle/build.sh
nl extension pack examples/extensions/java-lifecycle/build/package \
  --output java-lifecycle.nlext --private-key /secure/location/ed25519-signing.pem
nl extension verify java-lifecycle.nlext --public-key /secure/location/ed25519-verify.pem
```

Register the publisher public signing key in the **existing** registry/trust policy, then publish and install using the existing NeverExtensions workflow. `pack` can produce unsigned artifacts, but unsigned artifacts must not be trusted or installed. **Never** include private keys in a package or extension repository. Build metadata (`+...`) is preserved when checking exact package identity against the host.

## Actual behavior and limitations

- Manifest parser verifies schema, identity, target paths, dependency constraints and conflicting entries, with bounded JSON. The Go package verifier and signing/trust policy remain authoritative. Reading a manifest through this SDK does **not** verify a package signature.
- `SemVer` uses SemVer 2.0 precedence and NeverExtensions Go-style `^`, `~`, `>=`, `<=`, `>`, `<`, `=`, `x`, `*`, whitespace-AND and `||` version ranges. Invalid constraints are rejected instead of silently matching.
- `DependencyResolver.resolve(available, roots)` picks highest compatible versions, supports required/optional transitive dependencies, conflicts, backtracking and deterministic dependency-first startup order; cycles and unsatisfiable graphs fail. This local planner **does not** fetch packages or supersede the authoritative Go registry resolver.
- `Cancellation` supports cooperative cancellation, child scopes and exactly-once listeners; `Deadline` uses a monotonic clock; `ExtensionLifecycle` uses bounded waits, thread interruption and explicit transition states. Java cannot forcibly terminate an arbitrary noncooperative callback in the same JVM. The existing Go process supervisor is the final execution boundary.
- SDK Java code is **not** isolated or sandboxed within its own JVM; permissions are enforced by the existing Go host broker. No arbitrary JavaFX/LaunchServer/Gravit JAR compatibility is claimed.
- The current sample launchers are POSIX-specific. The Java SDK and tests run on Linux, macOS and Windows; a Windows executable wrapper and dedicated Java Extension Host are scheduled for subsequent releases.

## Shipped Java runtime APIs (0.30.3)

`ExtensionContext.runtime()` supplies **working** services after the runner connects to the Go host:

- `runtime().events().subscribe(type, "async" | "sync", schema, decoder, handler)` registers with the existing durable Go EventBus. `RuntimeCallbackServer` listens only on `127.0.0.1`, authenticates a separate callback token, validates the event envelope, and bounds callback execution to 1.8 seconds. Idempotency keys are exposed; handlers should deduplicate side effects when necessary because the bus is at-least-once.
- `runtime().commands().register(name, schema, decoder, handler)` registers commands only if declared in the extension's signed `cli.commands` manifest. The existing administrative `nl x <namespace> <command>` path starts a short-lived Java CLI target through the Go supervisor. `ExtensionRunner --cli` invokes the handler and prints JSON to stdout. `RuntimeCallbackServer` also supports authenticated `/v1/commands` callback calls, but Go's CLI target is the supported externally invocable path.
- `runtime().config()` and `runtime().storage()` read/write/delete extension-owned JSON documents over `runtime.config.*` and `runtime.storage.*` broker capabilities. Go enforces `storage:read`/`storage:write` on **every** request, including after revocation. Documents are segregated by extension ID and installation scope and survive package updates/restarts; 128 KiB per key, 256 keys and 4 MiB per extension+scope.
- `runtime().secrets().withSecret(name, projectId, callback)` uses the existing encrypted Go `secret.get` broker. A fresh `secrets:read` grant is required; the SDK zeroes the temporary decoded byte array after the callback. The application must not persist or log secret copies.
- `JsonSchema` rejects unknown keywords and validates the implemented strict subset: object/array/string/number/integer/boolean/null, properties, required, additionalProperties (boolean), items, enum, min/max-length, min/max-items, minimum, maximum. **Not** a complete JSON Schema 2020-12 implementation. Validation is done on config reads+writes, event payloads and command input before user callbacks.

Live backend/CLI demonstration:

```bash
sh examples/extensions/java-runtime/build.sh
python3 examples/extensions/java-runtime/test-runner.py
# Prepare a signable package with existing nl extension pack/sign/verify commands.
```

`Java SDK Runtime` operates on the **existing** NeverExtensions host process, permissions, signing and local event protocol. Go-host state is not OS-isolated from untrusted programs running under the same filesystem user; deployments requiring hostile-code isolation must use an OS sandbox/container/user boundary and access control for `data/extensions`. JVM is not a sandbox. Native Windows launchers and the separate Java Extension Host are planned for later milestones.


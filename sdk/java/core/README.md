# NeverLauncher Java SDK Core / Runtime 0.31.0

A **working Java 17+** SDK for the existing Extensions API `1.0` / Manifest `2.0` / local Go Extension Host Protocol `1.0`. The SDK does not introduce another manifest, server API or registry. No Maven dependency download is needed to build its jar.

## Build and run tests

```bash
sh sdk/java/core/build.sh test
# Output: sdk/java/core/build/neverlauncher-java-sdk-core-$(cat VERSION).jar
sh examples/extensions/java-lifecycle/build.sh
python3 examples/extensions/java-lifecycle/test-runner.py  # Linux/macOS, requires Java on PATH
```

The core jar can be included in an extension package as `backend/lib/neverlauncher-java-sdk-core.jar`; all Java classes are compiled with `--release 17`. Cross-platform Java 17/21 CI builds and tests the SDK, and Linux CI launches the example as a real child process.

## Runnable extension

Implement `ru.neverlauncher.sdk.core.Extension` with `start(ExtensionContext)` and `stop(ExtensionContext)` methods. The provided `ExtensionRunner` loads the implementation class, validates its shipped manifest and its host identity, performs a real authenticated `POST /v1/hello`, maintains `POST /v1/heartbeat` and executes lifecycle methods on managed executor threads. Exit when the host becomes unreachable or on process shutdown.

A Linux/macOS backend target is an executable launcher script (see `examples/extensions/java-lifecycle/backend/bin/java-lifecycle`). The existing Go supervisor launches it with the active package payload directory as working directory, injecting the `NEVERLAUNCHER_EXTENSION_*` environment variables. The extension process **must not be launched as a general network-facing service**; the SDK accepts only the loopback host origin. `ExtensionRunner` supports typed subscriptions and callback dispatch. For first-class JAR launch, use the 0.30.4 Java Extension Host described below.

## Packaging with existing Extensions CLI

```bash
sh examples/extensions/java-lifecycle/build.sh
nl extension pack examples/extensions/java-lifecycle/build/package \
  --output java-lifecycle.nlext --private-key /secure/location/ed25519-signing.pem
nl extension verify java-lifecycle.nlext --public-key /secure/location/ed25519-verify.pem
```

Register the publisher public signing key in the **existing** registry/trust policy, then publish and install using the existing Extensions workflow. `pack` can produce unsigned artifacts, but unsigned artifacts must not be trusted or installed. **Never** include private keys in a package or extension repository. Build metadata (`+...`) is preserved when checking exact package identity against the host.

## Actual behavior and limitations

- Manifest parser verifies schema, identity, target paths, dependency constraints and conflicting entries, with bounded JSON. The Go package verifier and signing/trust policy remain authoritative. Reading a manifest through this SDK does **not** verify a package signature.
- `SemVer` uses SemVer 2.0 precedence and Extensions Go-style `^`, `~`, `>=`, `<=`, `>`, `<`, `=`, `x`, `*`, whitespace-AND and `||` version ranges. Invalid constraints are rejected instead of silently matching.
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

`Java SDK Runtime` operates on the **existing** Extensions host process, permissions, signing and local event protocol. Go-host state is not OS-isolated from untrusted programs running under the same filesystem user; deployments requiring hostile-code isolation must use an OS sandbox/container/user boundary and access control for `data/extensions`. JVM is not a sandbox. The 0.30.4 Java Extension Host supports direct JAR targets on Windows, macOS and Linux. Legacy POSIX example launchers remain available; do not rely on a JVM security sandbox.


## Java Extension Host (0.30.4)

`backend` and `cli` manifest targets may point directly to the same **fat JAR** rather than a shell script. Build a JAR containing the SDK (`ru.neverlauncher.sdk.host.JavaExtensionHost`), extension implementation classes and the JAR main attributes:

```
Manifest-Version: 1.0
Main-Class: ru.neverlauncher.sdk.host.JavaExtensionHost
NeverLauncher-Extension-Class: org.example.MyExtension
```

NeverLauncher Go validates the JAR before execution, launches it as `java -jar <entrypoint>` using an administrator-configured Java executable or `java` from PATH, and passes **only** sanitized Extensions environment variables. The JAR must be within the signed `.nlext` package, with its `backend` target entrypoint declared in the signed manifest. Before hello, the Java host fetches the **authoritative manifest** from the authenticated Go `GET /v1/manifest`; no copied manifest in the payload is required or trusted. A Java target is considered healthy only after an authenticated `POST /v1/ready`, sent **after** `Extension.start()` succeeds. `hello` alone does not mark Java startup as complete.

The JVM opens an authenticated loopback callback server. The existing Java→Go broker/host remains the sole way to access backend capabilities. Go→JVM RPC is `POST /v1/rpc`, with a versioned envelope, a per-request nonce, a maximum 64 KiB body/response, explicit method allowlist (`health`, `command.invoke`, `event.deliver`, `hook.deliver`) and a maximum 1.8s deadline. Java callback handlers run in bounded thread pools/queues; a noncooperative callback can exhaust them, but Go does not wait indefinitely. The Go supervisor periodically issues concurrent liveness probes and terminates an unresponsive JVM after three consecutive RPC health failures, even when regular heartbeats continue. Existing process tree memory/process limits, restart backoff and crash-loop handling still apply. All event and command permissions continue to be enforced in the Go broker and Java's declared CLI command registry.

Build and run a working example:

```bash
sh examples/extensions/java-host/build.sh
python3 examples/extensions/java-host/test-runner.py
nl extension pack examples/extensions/java-host/build/package --output /tmp/java-host.nlext --private-key /secure/signing-key.pem
```

Java 17+ is required on the backend host. The Java runtime itself is an external administrator dependency: deployments can pin its absolute executable path using the Go `extensionhost.Config.JavaExecutable` field. A fat JAR is not sandboxed and runs with its process user's permissions. Publisher signing only proves package provenance, not harmlessness; hostile packages require an OS-level sandbox/container/service account boundary. Go unit/integration tests and the CI Java-host E2E workflow must pass for release certification. No arbitrary Gravit/LaunchServer JAR compatibility is implied.

The `java-host` sample includes a deliberately noncooperative `hang` command strictly for supervisor resilience tests. Do not deploy this sample in production.

## 0.42.1: Host/SDK 1.0 binary and wire compatibility

`Host Protocol` and `Extension API` remain `1.0` when the product version changes.
The authenticated JSON `POST /v1/hello` request retains all 0.42.0 fields,
including `protocolVersion`, `extensionApiVersion`, `instanceId`, `extensionId`,
and `pid`, with an optional `callbackUrl`. Extensions built against 0.42.0
continue to use that exact wire request.

After the host returns its signed-instance identity and negotiated list, the
Java SDK refuses undeclared or non-granted broker operations **locally before
sending HTTP requests**. For a host-dependent startup prerequisite, call
`host.connect(callbackUrl, Set.of("runtime.config.get"))`; absent capabilities
cause `HostSession.CompatibilityError` with code `HOST_CAPABILITY_UNAVAILABLE`.
This overload also works with 0.42.0 hosts because it does not alter the wire
request. Java code that calls only `connect()` or `connect(callbackUrl)` remains
source/binary compatible, and still gets runtime capability checks per call.

The SDK validates the independent `eventProtocolVersion`, available event names,
heartbeat period and response identity. Missing event types cannot be subscribed
to. `HostSession.HostError.code()` exposes structured reason codes emitted by
0.42.1 Go; old plaintext Go errors continue to expose `HOST_HTTP_<status>`.
Repeated hello requests and capability calls before hello are rejected. A
managed Java extension class is initialized and constructed only **after** a
successful authenticated hello, before lifecycle `start()`; `ready` requires a
positive acknowledgement from the Go supervisor.

Go now advertises `runtime.config.delete` and `runtime.storage.delete` only
when the existing `storage:write` permission is effectively granted; broker
checks remain authoritative on every operation (including after revocation).
The Go supervisor returns `409` with `error` and `code` for incompatible
protocol/API, process identity, unsupported callback and hello replay. None of
these changes adds a public endpoint or weakens permission checks.

Run `sh sdk/java/core/build.sh test` for real loopback HTTP compatibility
regressions, including the original 0.42.0 hello envelope. Full integration
against a production Go host still requires Go 1.27.3 and the existing release
matrix; a JVM HTTP fixture alone is not release certification.

## 0.42.3: durable subscriptions and event envelope sizing

Java `runtime().events().close()` now closes only local callback handlers. Backend subscriptions remain durable, so an update or JVM restart does not erase the pending EventBus backlog. To intentionally delete a subscription, invoke `runtime().events().unsubscribe(eventType, mode)` while the host session is active. The EventBus is at-least-once and callers must deduplicate non-idempotent side effects.

The authenticated callback server accepts event/hook envelopes up to 2 MiB to carry the existing 1 MiB EventBus payload limit; authenticated command/RPC requests retain their separate 64 KiB bound. Java `null` is a valid JSON command result. Full documentation and tests: `docs/extensions/eventbus-rpc-persistence-0423.md`.

# NeverLauncher 0.48.3 — Java SPI и действующий реестр провайдеров расширений

A signed Java extension can define a typed SPI contract, register multiple implementations and choose one provider at runtime. This is a working **in-process registry scoped to a single supervised extension JVM**, not a cross-extension service bus, a new HTTP endpoint, a package installer or a way to bypass Go capabilities. The JVM continues to use the locked nested-JAR dependency loading from 0.48.2; `ru.launcher.sdk.*` remains parent-loaded.

## Промышленный API

An SPI service is a Java interface extending `JavaProvider`, for example `GreetingProvider` with `greet(String)`. In `Extension.start(ExtensionContext ctx)`:

```java
ProviderService<GreetingProvider> greeting = new ProviderService<>(
    "example.greetings", GreetingProvider.class, SemVer.parse("1.1.0"));
ctx.providers().register(new ProviderDescriptor<>(greeting, "friendly",
    SemVer.parse("1.0.0"), ">=1.0.0 <2.0.0", "^1.0.0", Friendly::new));
ctx.providers().register(new ProviderDescriptor<>(greeting, "formal",
    SemVer.parse("1.0.0"), ">=1.0.0 <2.0.0", "^1.0.0", Formal::new));
ctx.providers().select(greeting.id(), "formal", Duration.ofSeconds(2));
String text = ctx.providers().call(greeting, p -> p.greet("Ada"));
```

`ProviderDescriptor` declares both the supported **SPI interface version range** and the supported **signed extension API version range**. Unsupported versions, service-interface mismatches, duplicate provider IDs, unregistered selections and factories returning the wrong type are rejected. Compatibility checks precede factory execution, and the existing Go package verifier and Java locked-library inspector still reject bytecode/package conflicts independently. No JAR is dynamically fetched or appended to the core classpath.

`select` is a bounded, synchronous operation: it drains concurrent `call` leases, calls `stop` on the old implementation, constructs and starts the new implementation, then publishes it atomically. Selection of the currently active ID is idempotent. If startup fails, the candidate receives best-effort cleanup and **no provider remains active**; no silent fallback to a previous implementation occurs. The caller is responsible for persisting the chosen ID if desired, using the existing authenticated `runtime().config()` broker and appropriate permissions; there is no untrusted local fallback file. During provider switching new invocations fail immediately rather than being routed to a half-started instance.

`ExtensionLifecycle.stop()` first calls the extension's stop callback, then drains and stops all active registered providers. Extension startup errors also close already-started providers. Concurrent close callers wait for the first shutdown's result. A Java callback ignoring interruption may remain alive in a daemon worker, but **cannot be forcibly terminated by the JDK**: the existing Go process supervisor and OS isolation remain mandatory. Provider code has exactly the extension JVM's privileges and must use Go RuntimeServices for backend operations; this SPI is not a security sandbox.

## Работающая интеграция

```sh
sh sdk/java/core/build.sh test
sh examples/extensions/java-spi/build.sh
python3 examples/extensions/java-spi/test-runner.py
```

The example builds an extension and a *distinct pinned library JAR*, embeds the library into the host package, and starts the real `java -jar` under the authenticated Host Protocol 1.0. It reads the active provider from a broker-backed config document (`spi.active`) and refuses startup if it is unknown. The integration then tests `formal` provider invocation, switching to `friendly` over the existing authenticated CLI-command RPC, the unknown-ID rejection, heartbeat, CLI startup and invocation, clean shutdown, and rejection before `/v1/ready` when the persisted choice is invalid. The runnable example's HTTP server is an integration fixture; production continues to use the real Go host and signed package path.

To package for an installation, sign `examples/extensions/java-spi/build/package` with the established `nl extension pack` signing flow and install through the existing verified Extensions manager. Do not deploy unsigned local test fixtures. The example does not claim arbitrary cross-extension providers, discovery of unrelated Maven modules, or general auth/content/ServerBridge SPI (planned for later releases).

**Certification:** CI exercises Java 17/21 on Ubuntu/macOS, and the locked-library inspection under the pinned Go toolchain. Local testing under Java 21 is not a substitute for the full product's independently certified PostgreSQL cutover, existing release gates or native signed installer acceptance. Production GA must remain fail-closed until those gates pass.

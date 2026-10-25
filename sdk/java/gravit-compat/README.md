# Gravit Compatibility Adapter 0.30.7

This is a **working, deliberately limited source-port adapter** for GravitLauncher-style Java modules, not a universal Gravit JAR loader. It runs in NeverLauncher's existing Java Extension Host (`java -jar`) under Go supervisor deadlines and Ed25519-signed `.nlext` package verification. Gravit's internal LaunchServer/LauncherRuntime/JavaFX APIs are not present and are not emulated. This code is independently implemented and is not a copy of Gravit sources.

## Supported API (fixed list)

| Type / API | Actual NeverExtensions behavior |
|---|---|
| `pro.gravit.utils.Version` | 4-component integer version, compare, `Type`, `getVersionString` |
| `pro.gravit.launcher.base.modules.LauncherModule`, `LauncherInitContext` | `preInitAction` + `init`, bounded by Java Extension Host lifecycle. Context is a `GravitInitContext` exposing real `ExtensionContext` |
| `LauncherModuleInfo`, `LauncherModuleInfoBuilder` | Local module metadata; legacy internal Gravit dependencies rejected instead of silently treated as satisfied |
| `LauncherModule.EventHandler`, `registerEvent()` | Typed adapter over Go's **real** EventBus. Only whitelisted `@HostEvent` types with existing EventBus types are accepted |
| `ReleasePublishedEvent`, `ProjectSavedEvent` | Binds respectively to `release.published`, `project.saved`, preserving event id/project/idempotency key and raw JSON payload |
| `pro.gravit.utils.command.Command`, `CommandHandler.registerCommand()` | `invoke(String... args)` runs via NeverExtensions authenticated RPC/CLI command registry; command names must be declared by a signed `.nlext` manifest; `CommandHandler.respond(Object)` returns bounded JSON output |
| `AutoCloseable` module | `close` called at extension stop; all event subscriptions removed by existing RuntimeServices on exit |

**Not supported**: binary compatibility with unmodified upstream modules, `LaunchServer` internals, `LaunchServerInitContext`, `LaunchServerPostInitPhase`, `PreConfigPhase`, providers/registries, `ModulesConfigManager`, JavaFX UI, `Event.cancel()` and cancellation semantics, arbitrary Gravit `CommandHandler` internals, unchecked classpath dependencies. Calls to unsupported cancellation or event types are rejected, not silently accepted. Port source against this published subset, use NeverExtensions `ExtensionContext.runtime()` for config/storage/secrets, and declare permissions/dependencies in the signed package. Gravit package names are used only for the documented subset, not to promise ABI parity across Gravit versions.

## Build, run and package

```sh
sh sdk/java/gravit-compat/build.sh test
sh examples/extensions/gravit-compat/build.sh
python3 examples/extensions/gravit-compat/test-runner.py
# Requires NeverLauncher CLI and a pre-existing protected Ed25519 private key
nl extension pack examples/extensions/gravit-compat/build/package --output /tmp/gravit-port.nlext --private-key /secure/extension-private.pem
nl extension verify /tmp/gravit-port.nlext --public-key /secure/extension-public.pem
```

For each ported module, build a self-contained JAR with:

```
Main-Class: ru.neverlauncher.sdk.host.JavaExtensionHost
NeverLauncher-Extension-Class: ru.neverlauncher.sdk.gravit.GravitCompatExtension
NeverLauncher-Gravit-Module-Class: your.package.YourPortedModule
```

The Java SDK, adapter and ported class must be packaged in this JAR. Go's `extensionjava.Inspect()` verifies that the adapter and module class are present **before** a Java process is launched; signature verification and issuer trust remain in existing NeverExtensions package lifecycle. No automatic loading of arbitrary Gravit JARs or dependencies on external `Class-Path` is allowed. Compile with Java 17+; Java 21 is also covered by CI.

Example `PortedModule` subclasses `LauncherModule`, receives a real `release.published` event, writes a persistent record through Go storage broker, and exposes a declaratively authorized `status` CLI command. The subprocess E2E boots an actual JVM-host JAR, verifies the hello/ready/heartbeat loop, invokes an authenticated RPC event callback, reads state from a second JVM CLI invocation, rejects invalid tokens and undeclared commands. Host simulation in the E2E tests only the transport; test on an actual deployed Go backend before certifying production rollout. Commands execute in a **trusted Java OS process**, not a sandbox.

Upstream API signatures checked against `GravitLauncher/Launcher`'s `LauncherModule`, `LauncherModuleInfoBuilder` and `Command` sources (master as of 2026-10-25). The actual API surface is intentionally smaller; binaries linked against the full upstream libraries are not accepted as compatible. See `docs/releases/0.30.7-gravit-compat.md` for tested boundaries.

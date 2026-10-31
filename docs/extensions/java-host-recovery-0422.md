# Java Extension Host: subprocess recovery (0.42.2)

The extension package must already be installed, verified and **enabled** by the lifecycle manager. Its `backend` target must be an inspected executable `.jar` containing the published `JavaExtensionHost` entrypoint; the JVM is launched as a separate OS process by the Go Extension Host Supervisor, not loaded into the Backend JVM. Host Protocol and Extension API remain at `1.0`.

## Operational behavior

- `StartInstallation` checks persistent kill-switch/quarantine, the enabled state, the package manifest, and the granted effective permissions. It validates its payload entrypoint and resolves a trusted configured absolute Java path (or Java from PATH). The JVM receives only the minimum host instance credentials and a sanitized environment.
- Java sends an authenticated `hello`, starts the extension, then sends `ready`. A failed OS start or missing Java installation records `state=failed` with `lastError` and retires the one-time token. Fixing the executable or package permits a new start; the old credential is not reused.
- Unexpected JVM exit, heartbeat expiry or a nonresponsive authenticated Java RPC callback ends the process tree and starts **bounded** recovery. Each attempt rereads the durable installation, requiring the same generation, package identity and enabled state; no retry is permitted after a stop, disable, uninstall, upgrade or replace operation revokes the recovery epoch. No Java bytecode is loaded into the Go Backend.
- When a retry fails before `exec` or during the startup readiness handshake, the system reaps the failed process and retries with bounded exponential backoff. Exceeding `CrashLimit` within `CrashWindow` transitions to `crashloop` and invokes the configured emergency-disable handler. Manual `Restart` clears the in-memory crash counter, but does not bypass the repository's persistent emergency disable.
- `Reconcile` skips already healthy installations, stops missing/disabled/obsolete generations and attempts restart of previously failed instances. It never automatically resets a crash-loop for the same package generation.
- The status reports JVM PID, `java-jvm` runtime, process/resource metrics (where supported), last heartbeat, exit code and reason, instance ID, restarts, and explicitly reported isolation. Java Host requires a **trusted** Java process and is not an OS sandbox by virtue of running out of process. The isolated Java mode stays unsupported until its reverse RPC transport meets the sandbox requirements.

## Validation

Build the original runnable extension JAR:

```sh
sh examples/extensions/java-host/build.sh
python3 examples/extensions/java-host/test-runner.py
sh sdk/java/core/build.sh test
```

On Linux with **Go 1.27.3 or newer** and Java 17/21, test the actual JVM Supervisor:

```sh
cd services/api
LAUNCHER_TEST_JAVA_HOST_JAR="$PWD/../../examples/extensions/java-host/build/package/backend/java-host.jar" \
    go test -race -count=1 -timeout 3m -run 'TestJava.*(0304|0422)' ./internal/extensionhost
go test -race -count=1 -run '^TestJavaLateHelloCannotUndoOperatorStop0422$' ./internal/extensionhost
```

The tests kill a **real Java child JVM**, observe a new PID/instance/health response, simulate missing Java during restart and repair the executable, check idempotent reconciliation, and prove that an explicit stop cancels scheduled resurrection. CI repeats this under the checked-in Java Host workflow. A green Java-only test does **not** certify Go process recovery or the six target OS platforms.

## Deliberate boundaries

- The backend keeps the Host Protocol `1.0` envelope; no arbitrary Gravit JAR binary compatibility is claimed.
- Operator stop/disable and package quarantine take precedence over automatic recovery. Crash-loop operator intervention is intentional.
- Linux process groups and RSS counts are not equivalent to Java OS sandboxing on every platform; check `Status.IsolationStatus`, not the process name.
- The project's existing final ServerBridge release acceptance and source-commit-bound evidence remain mandatory; version 0.42.2 does not imply production release certification.

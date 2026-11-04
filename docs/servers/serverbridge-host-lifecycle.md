# ServerBridge Host 0.41.4: verified JVM lifecycle

The Host Supervisor executes the real configured Java executable. Minecraft `stop` is sent to **stdin** of the verified child process, never to a historical PID. The service must own an exclusive host session before starting a JVM. The remote host API remains narrowly scoped to `start`, `stop`, `restart`, and `status` — it is not a shell interface.

## Install, start and observe

```bash
nl server-bridge host configure --server-root /srv/minecraft/paper --platform paper \
  --server-jar paper.jar --java /usr/bin/java \
  --restart-policy on-failure --max-restarts 3 \
  --restart-backoff-ms 2000 --stop-timeout-seconds 30
nl server-bridge host start --server-root /srv/minecraft/paper
nl server-bridge host status --server-root /srv/minecraft/paper
nl server-bridge host logs --server-root /srv/minecraft/paper --stream all --lines 100
nl server-bridge host restart --server-root /srv/minecraft/paper
nl server-bridge host stop --server-root /srv/minecraft/paper
```

The `start` exit code is zero only when the supervisor **and Java child** are alive with verified OS identities. `running` here means the JVM process is alive; it does **not** prove that Paper has finished loading worlds or that players can join. Game readiness is a separate ServerBridge heartbeat/readiness check. If startup times out, inspect `host status` and logs before issuing another action. Do **not** blindly retry an uncertain RemoteControl operation with a different idempotency key.

## Termination and crash semantics

- A normal `stop` delivers `stop\n` to the running Java process's stdin, waits for it to exit and persists the final runtime state. A SIGTERM sent to the Host Supervisor is handled through the same graceful child shutdown path.
- When no graceful exit occurs within `stopTimeoutSeconds`, the supervisor escalates to the process group **only after** verifying the OS process identity; the stop method records `terminate` or `kill`. This is a last resort and is **not** equivalent to a confirmed Minecraft world save.
- When the JVM terminates unexpectedly, the supervisor saves the exit code and crash count, and applies `restart-policy`, `max-restarts`, `restart-backoff-ms`, and `crash-window-seconds`. Stop or SIGTERM during backoff prevents the pending new Java process.
- A supervisor that dies abruptly cannot safely adopt a still-running child from an earlier process session. The next start fails closed. Inspect/stop the orphan **manually**, verifying the process identity and its data, then start a new supervised JVM.
- The RemoteControl idempotency receipt and Backend command journal still govern the action **at most once**; observed OS state is not proof that an arbitrary Minecraft command has executed. An uncertain receipt remains uncertain, and does not authorize automatic replay.

## Verification in source checkout

```bash
cd cli
GOTOOLCHAIN=local go test ./cmd/launcher -run 'TestHostLifecycle0414' -count=1 -v
GOTOOLCHAIN=local go test ./cmd/launcher -run 'TestHost0282|TestJVM0283' -count=1
```

On Linux with `java`, `javac`, and `jar`, these tests compile and run an actual Java JAR, verify the OS executable (`/proc/<pid>/exe`), check Java-authored boot/exit/save markers, and test the **built CLI** rather than trusting mocked subprocesses. The integration fixtures use a small Java test server and do not claim to validate a commercial Paper/Folia server distribution. Full Minecraft-version compatibility and backend/host cross-node recovery require additional lab testing.

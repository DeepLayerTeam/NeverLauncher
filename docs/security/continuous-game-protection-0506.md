# Guard 0.50.6 — Continuous Game Protection

## Executable behavior

1. Runtime verifies the signed release, the active selected file set and the external Ed25519 Guard policy before creating Minecraft JVM.
2. Both the blocking launch entrypoint and `ProcessSupervisor` keep an independent **native watchdog** for the whole game process. Every five seconds (plus actual filesystem verification time) the watchdog reopens and SHA-256 hashes approved JAR/native executables. It also verifies the current policy signature, project/Minecraft/loader scope, validity, revocations, and that the accepted policy digest has **not changed during this game session**. New/changed mods or native libraries in managed directories are rejected by the existing compatibility-policy checks. Checks execute on blocking workers outside the async reactor.
3. On verification failure, the parent terminates the game. `ProcessSupervisor` stores `trust-blocked`/`guard_violation` so even a zero exit code cannot turn the incident into a successful game. The one-shot launcher writes the reason to the launch log and records unsuccessful launch history.
4. On guarded JVMs, the existing Java Runtime Integrity watcher checks the executable files and Linux mapped native images. A **second JVM thread** terminates the game if the primary integrity watcher has exited or has not completed a verification for 90 seconds. The existing Windows Guard Sensor retains its authenticated process/event-chain heartbeats and native memory/module checks.
5. The Desktop `ProcessSupervisor` now uses the same signed Trusted JVM agent preparation, JVM arguments and guarded original-main wrapper as the native one-shot launcher, and retains the private agent configuration until child exit.

## Deployment prerequisites

- Keep the externally pinned `LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE` and accepted epoch state protected from the player's account where possible. Set `LAUNCHER_GUARD_COMPAT_REQUIRED=1` on protected deployments. The policy and release file set must be installed and valid for the exact active game build and loader.
- A signed policy must remain unchanged for a running game. Publish changed/revoked policies by stopping or ending affected sessions and starting a new verified session. Mid-game policy rotation is intentionally a fail-closed decision.
- Confirm supported Windows/macOS/Linux x64/ARM64 packages with the CI native matrix. Run real loader/Minecraft joins separately; synthetic OpenJDK tests are not Minecraft certification.

## Tests

- `python scripts/tests/continuous_game_protection_0506.py` — real JVM normal run and forced interruption of Java integrity watcher.
- `python scripts/tests/guard_runtime_integrity_0505.py` — previous seven real-JVM file/native integrity regressions.
- `cargo test --manifest-path runtime/runtime/Cargo.toml --lib continuous_game_protection_0506` — native hash-change and real subprocess termination tests on Unix; file integrity checks on other hosts.
- `.github/workflows/continuous-game-protection-0506.yml` — six-platform native compilation and JVM regression jobs.

## Limitations and fail-closed boundaries

User-mode observers cannot protect against malicious code with complete access to the same JVM or operating-system account. Native process checks rehash filesystem bytes, not all executable pages or third-party class transformations in memory. On Windows, the separate Sensor is required for native module/process/event-chain coverage; Linux `/proc/self/maps` monitoring is in-process, while macOS mapping coverage remains limited. No automatic server-side enforcement/penalty is introduced here; server-bound Guard sessions are the separate 0.50.7 milestone. Successful local tests do not constitute release GA acceptance.

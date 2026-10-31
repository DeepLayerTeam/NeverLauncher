# 0.34.10 V10 — Native runtime runner operations

## Guarantees and trust boundary

- The capability registry runs **on the worker**, not in CI configuration. It verifies the actual selected Java binary, native display and OpenGL renderer, OS and architecture. GPU inventory, PID, `DISPLAY` alone, a completed timeout and an uploaded JSON are **not** positive startup evidence.
- Supported OS/architectures: Windows amd64/arm64, Linux amd64/arm64, macOS amd64/arm64. A host which cannot actually supply the GUI driver, desktop session, renderer or required permission returns **blocked**. Hardware compatibility is **not** certified by being listed here.
- Headless runner downloads **the exact staged package bytes** with the limited grant, performs normal transactional `client install`/`verify`, and reports all GUI/runtime stages as `blocked`. A headless pass **never** proves startup, matching server, gameplay or V09.
- The Linux pinned OCI worker is still the only independently attested runtime in V04/V06. A Windows/macOS **observational** run is not independently signed ValidationEvidence and cannot grant stable publication. Other architectures must have a separately approved trusted attestation worker; this release does not silently convert native CI artifacts into signed evidence.
- Backend stable publication remains fail-closed.

## Prerequisites

- Dedicated self-hosted OS user, no production data or signing keys, disposable worker VM/snapshot; outbound connections allowlisted for staged delivery, live provider and pinned server dependencies. Do not run GUI E2E unattended on a shared interactive workstation.
- `python >=3.11`, Go toolchain from `cli/go.mod`, Rust toolchain for `Runtime`, Java runtimes for all supported target majors, real staged package grant/operator credentials, exact prior-release and pinned ServerBridge artifacts, properly authorized real-provider test accounts. No mock provider for V07.
- GUI workers require `psutil`, Pillow, `glfw`, `PyOpenGL`, `pynput`, Tesseract (English OCR) and a working native desktop. **macOS:** additionally `pyobjc-framework-Quartz`, Screen Recording and Accessibility grants for the dedicated agent account. **Windows:** unlocked interactive desktop; service session 0 / disconnected RDP is blocked. **Linux:** `DISPLAY`, `xwininfo`, `xprop`, `scrot`, `identify`, `tesseract`, `glxinfo`, `xdotool`, functional GLX/OpenGL (software renderer accepted if functional). No assumption that a GitHub-hosted runner is GUI-capable.
- GUI proof is only for an English main menu with two recognizable Minecraft controls and an actual window belonging to the selected Java binary. Other localizations/themes require separate real probes; they are not auto-certified.
- On Windows, modded matching servers may use a pinned `run.bat` or direct Java JAR; Unix `run.sh` is rejected. Windows local workers need Git Bash if using the supplied workflow. Headless does not run a matching server.

## CI and local execution

`native-runtime-v10-03410.yml` is opt-in `workflow_dispatch` (package ID, OS, architecture, execution mode). A matching dedicated runner must bear **all** labels: `self-hosted`, `nl-validation`, `nl-<os>`, `nl-<arch>`, `nl-<mode>`. Only explicitly provisioned runners execute these jobs. Jobs compile the real production CLI and Runtime, run platform probes, use a private per-job temporary directory, and export a restricted set of JSON diagnostics. Failure or lack of a renderer means **BLOCKED**, not false incompatible-Minecraft **FAILED**. The published CI artifact is observational.

Manual capability check, with an actual executable Java path:

```sh
python3 e2e/scripts/runtime_capabilities_03410.py --mode gui --java /path/to/java --output /tmp/nl-capability.json
```

Exit 0 means the worker is ready to **attempt** the chosen scenario, not that Minecraft works. Exit 3 means blocked. The report contains actual renderer version and Java SHA-256. A nonempty `blockers` array always prevents positive readiness.

Use `run_native_validation_03410.py --mode gui --report-dir /safe/reports -- [run-staged-package flags, excluding --output]` for the bounded and isolated observational run. For headless use `--mode headless` and do not present completion as gameplay. Worker stdout/stderr are not exported because they may contain live provider secrets; the allowlisted JSON reports are copied before the whole isolated work directory is deleted. Do not retain jobs' grant, token files or raw logs on shared hosts. Centralized redaction/retention remains V12.

## Negative acceptance

1. Stop or disconnect the GUI session / make OpenGL context creation fail: capability status `blocked`, startup not `passed`, no attestor signature.
2. Provide wrong/nonexecutable Java: `blocked` before Minecraft launch.
3. Headless runner with a correct staged JAR: manifest/materialization `passed`, startup/gameplay `blocked`, never signed.
4. Window from a different process: not recognized as selected Java, no startup PASS.
5. Drop macOS Accessibility or Screen Recording permission: `blocked` even if Java and GPU are installed.
6. Terminate updater in staging and committing: invoke public recovery, require a verified retry and rollback; merely killing a PID is not PASS.

## Scope of verification

This source tree includes executable native observers, capability checks and process-tree lifecycle handling; only Linux tests can be executed in a Linux development container. To claim target-specific production readiness, execute the **actual** native workflows on dedicated Windows/macOS/arm64 hardware with the real signed staged package, GUI permissions, Java, server and account fixtures. A green unit test does not establish platform compatibility.

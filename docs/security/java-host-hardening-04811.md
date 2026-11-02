# 0.48.11 Java Host security hardening and acceptance boundaries

Java Host runs as an OS process but **does not acquire kernel filesystem/network isolation** from `URLClassLoader`, `-Xmx`, or an authenticated loopback RPC token. Never label a legacy JVM launch as `os-isolated`.

Implemented in the actual Java Host and Java CLI startup paths:

- Java executable selected via absolute verified path; PATH-based selection resolves the JDK alternatives symlink and verifies the resulting file.
- Heap/metaspace/direct memory/code cache limits, attach disabled, core dumps disabled, unchanged Go RSS and process count monitor. The process tree monitor runs periodically and is not a hard kernel memory cgroup limit.
- Per-instance temporary directory (0700) for Java user home, caches and temp files, removed when a persistent JVM exits or transient CLI completes. This does not prevent direct reads of other paths by a JVM running under the same OS user.
- `secret.get` rejects JVM callers. Only OS-confined trusted brokers should handle opaque credentials; do not send raw secrets to legacy JVM.
- Authenticated Java clients receive existing per-instance host request limits (rate, concurrent requests, output budget). Host/CLI logs mask the live host/callback bearer credentials and key-labeled secret fields; **arbitrary extension-supplied values cannot be proven secret-free**.
- Existing outbound HTTP broker pins DNS results to an approved public IP, forbids private/special-use addresses, verifies TLS and disables redirects. **Unconfined Java code can bypass the broker through its own sockets.**
- An extension requesting `sandbox.mode=isolated` with a JVM backend is rejected before exec because authenticated reverse callbacks across the current native sandbox boundary are not implemented. There is no insecure fallback to ordinary Java.

## Release acceptance

1. Java 17 and 21: compile and run SDK, launch actual Host JAR and CLI, verify scratch and resource constraints, reject raw secrets and test revocation/quotas.
2. Linux amd64/arm64: run existing cgroup2/userns/seccomp native sandbox adversarial tests in a delegated unprivileged service identity. Check JVM `isolated` fail-closed. Do not mark Java as kernel-isolated.
3. Windows x64 and macOS ARM64/x64: run their native AppContainer and signed App Sandbox helper tests on real OS runners with required privileges/signatures; verify JVM `isolated` fail-closed, process stop/cleanup and network denial for genuinely confined **native** processes.
4. Run full Go 1.27.3 race and HTTP integration suites, Java Host subprocess regression, production signed-payload release gates, PostgreSQL + Minecraft integration and independent operator acceptance. A green Java SDK suite alone is insufficient.

Until a dedicated Java reverse IPC broker inside OS sandbox is implemented and certified separately on each OS, this release provides **JVM defense in depth**, not secure confinement of arbitrary untrusted Java code. Do not run untrusted Java extensions with backend privileges.

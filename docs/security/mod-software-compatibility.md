# NeverLauncher 0.50.10 — Mod & Software Compatibility

## What actually changed

**Windows:** the in-process native Hook Engine now instruments the native modules in the game or Java installation, not the imports of arbitrary third-party DLLs. The independent Windows Module Guard continues to check **every loaded module**: the signed executable files from the game installation are hash pinned; DLLs outside trusted roots must pass the OS Authenticode verification. No substring/vendor-name based exclusions or environment-variable bypasses were added. Known caveat: third-party overlay hooks targeting an otherwise guarded game/JVM region may still trigger memory/hook integrity checks. External, signed overlays are *not* automatically proof of safety.

**Linux:** system libraries in a root-owned, non-group/world-writable `/usr/lib`, `/usr/lib64`, `/lib` or `/lib64` tree remain available. Other external executable mapped libraries (user-installed Vulkan layers/overlays, native capture components and vendor add-ons) are admitted only when their **exact absolute path and SHA-256** occur in the existing operator-signed, project/version/loader-bound Guard policy as `externalNativeModules`. Both the external Rust `/proc` observer and the JVM observer check the loaded path and hash during the session, with live policy/epoch checks. The Rust observer also compares mapped inode with the current file. Unknown or changed user-writable native modules are blocked. This does not grant them trusted Java hook privileges, or exempt mod JARs, JVMTI, unknown agents, process debuggers, or cheats.

**macOS:** retain existing Hardened Runtime and code-signature checks for Guard, user-mode JVM process checks and signed mod/native inventory. Screen/window recording in separate processes does not imply a JVM injection exception. Direct code injection is not authorized merely by naming OBS, a GPU vendor or an accessibility tool. No relaxation of SIP, AMFI or Gatekeeper is implemented.

### Updating the signed policy for a Linux overlay

1. Find the actual library path loaded by the application. Verify its package origin and permissions **out of band**; do not accept paths/hashes supplied by a game client or player.
2. Calculate `sha256sum /absolute/path/to/overlay.so`. Prefer a stable installation path with no symlink components. Paths under `/proc`, `/sys` or `/dev` are rejected. On systems with symlinked `/lib`, use a canonical path under `/usr/lib` where applicable.
3. Add the following *optional* field to the existing `launcher.guard-compatibility.v1` **payload** for the affected game/project/loader (leave it absent for policies without external libraries):

```json
"externalNativeModules": [
  {"path":"/home/example/.local/share/example/libcapture.so", "sha256":"<exact lower-case 64-digit SHA-256>"}
]
```

4. Increment `epoch`, review the entire signed payload, sign it **offline** using `go run ./cmd/guard-policy-sign --mode sign ...`, and install using the existing `launcher guard-policy-install` command. `guard-policy-verify` verifies the new policy, not the execution of the overlay. A new version/hash requires a new signed epoch; put an old digest in `revokedDigests` to revoke it.
5. Run the real game's launcher and Guard with the exact Vulkan/overlay configuration. A signed hash only attests to the installed bytes, not the absence of cheating. Do not set `LAUNCHER_GUARD_COMPAT_REQUIRED=0` as a compatibility workaround.

`externalNativeModules` is **Linux-only**; policies containing it are not accepted as working cross-OS policies. Up to 64 external native modules may be listed. Libraries must be actual regular files, at most 512 MiB; symlinked paths and their components are refused. Policies lacking this field are still valid with unchanged guard rules.

### Acceptance boundaries

Automated executable tests cover positive/negative actual Java/JNI runs with a native `.so` outside game root, external replacement, unknown external load, existing mod/JAR/classpath mutation, and Go signature/revocation tests. Windows hook-scope tests run in native CI, and independent Module Guard keeps signing checks. CI must compile Rust on each target before claiming support. There are **no completed real installations of OBS Studio, Discord/Steam overlays, antivirus suites or multiple NVIDIA/AMD/Intel GPU driver versions** in the evidence from the Linux authoring environment. Real hardware/application acceptance requires a matrix of installed software versions, enabled capture mode, Minecraft loader+mods, OS, GPU, driver, JVM and Guard report, with normal-join/long-run and controlled tamper negatives. Missing configurations remain BLOCKED; no assumption of universal support is made.

Release 0.50.10 GA is blocked until real host and Minecraft/ServerBridge runs as well as signed artifact verification and independent reviewer receipts have been collected.

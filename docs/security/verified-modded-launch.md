# NeverLauncher 0.50.3 — verified Minecraft JVM launch under Guard

This feature is **executable code** in the existing native Runtime launch function, not an alternate mock launcher. It uses `launcher.trusted-jvm.v1` packages installed by the existing `trusted-install` command and `launcher.guard-compatibility.v1` policies installed with `guard-policy-install`. Both signed material and external operator public keys are required; the native bridge never accepts a hash or a plugin list from the game process as an authorization.

## Operator procedure

1. Use the normal signed Minecraft profile/ClientFactory pipeline to install the exact Vanilla/Fabric/Quilt/Forge/NeoForge game files. The profile's loader/version and classpath remain governed by the release signature.
2. Install the trusted extension package with `launcher runtime client-factory trusted-install --client-dir <CLIENT> --package <SIGNED_NLEXT> --public-key <EXTERNAL_TRUSTED_KEY> --approve-full-jvm-access true`. This is **fully trusted** JVM code, not an isolated plugin.
3. On the operator's separate secure workstation produce a Guard compatibility policy containing the exact `projectId`, Minecraft version, loader, SHA-256 entries for all enabled `mods/*.jar`, required native libraries, and the immutable `.launcher/trusted-jvm/releases/<PACKAGE_SHA256>/agent.jar` and `plugins/*.jar`. Authorize only reviewed `transformations: [{"id":"net.minecraft.client.Minecraft", "ownerSha256":"..."}]`. Use the shipped Guard signer and install the signed policy. Details: `docs/security/guard-compatibility.md`.
4. Set the **external** `LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE` and `LAUNCHER_GUARD_COMPAT_REQUIRED=1` in the operator-controlled launcher environment. The Trusted Java install/maintenance commands additionally use `LAUNCHER_TRUSTED_JVM_PUBLIC_KEY_FILE`, but the native Runtime depends on the separately signed Guard allowlist at *every spawn*. Do not put public trust anchors under the modifiable game directory.
5. Launch the normal signed Minecraft release through native Runtime (or ClientFactory's existing legacy launch path for older Java 8 clients). Native Runtime rechecks the installed signed-package SHA-256 and the Guard-signed code bytes, creates a unique private `.guard-launch-*.properties` premain config, passes an exact `-javaagent` for the approved launcher agent, and runs the loader's original Java main through `ru.launcher.trusted.MinecraftMain`. The premain hash-checks plugins and applies class-transform restrictions. The temporary configuration is removed after JVM exit.

## Fail-closed behavior

- Installed trusted package with no signed Guard policy, unrecognized signed scope, damaged/expired/revoked policy, missing/changed JAR, unexpected mod/native, or unapproved plugin/transform: launch is refused **before** the JVM starts.
- Unknown `-javaagent`, `-agentpath`, `-agentlib` and debugging options remain disallowed by the existing Runtime/Windows Sensor. A valid policy is not a blanket waiver for unrelated agents.
- A signed Java module entrypoint cannot silently be replaced by the classpath wrapper. The native launcher refuses this combination if a Trusted JVM package is installed. Unprotected builds without a Trusted JVM package use the existing normal launch behavior.
- On Windows the Guard Sensor still requires verified startup DLL, authenticated IPC, locked-down process policy and native module checks; the approved startup Java agent is checked against the signed **installation** root, which need not equal the JVM game working directory.

## Acceptance required before GA

Run the `guard-compatibility-0502.yml` six-platform CI matrix, including native `guarded_trusted_launch_0503` signed-policy tests. Independently download final signed packages on Windows x64/ARM64, Linux x64/ARM64 and macOS x64/ARM64, install actual loader versions (Vanilla/Fabric/Quilt/Forge/NeoForge as supported), launch the exact modded client with the trusted hook, log in and join a real Minecraft server, observe authorized gameplay, then repeat with modified/extra mods and agents. Record platform/JDK/loader/game build hashes, Guard IPC evidence and process exit reasons. A real Java fixture is not Minecraft E2E and CI declaration is not CI execution. The uploaded project cannot be called GA until that independent evidence and preexisting release gates pass.

### Security boundaries

This policy prevents unauthorized *startup* artifacts within the supported launcher boundary; a player with control of the OS can still tamper with user-mode processes, environment, in-memory behavior or local anti-rollback state. The trusted JVM agent has full Instrumentation privileges; its callback allowlist does not sandbox malicious trusted code. Continuous runtime revocation and server-bound proof are separate 0.50.6/0.50.7 tasks, not claims made by 0.50.3.

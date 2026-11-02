# NeverLauncher 0.50.4 — verified loader class origins and authorized JVM hooks

## What is enforced by running code

With an installed operator-signed Guard compatibility policy and an active Trusted JVM package, both the Rust Runtime and the Go legacy launcher now pass the **signed loader identity and pinned runtime loader JARs** into the Java `premain`. The agent registers an actual `ClassFileTransformer` **before** loading extension hooks or executing the original loader entrypoint. It checks the `ProtectionDomain.CodeSource` of loaded loader infrastructure classes, compares the source to an approved canonical JAR pathname, and verifies SHA-256. The source must belong to the signed policy's `loader-library` entries. Wrong loader, unpinned classes, changed JAR, missing policy binding, missing code source, and revoked loader JARs fail closed. Exceptions from Java Instrumentation are not relied upon for denial: the process halts with code 79.

Classification covers `net.fabricmc.loader.impl.*` (Fabric), `org.quiltmc.loader.impl.*` (Quilt), `net.minecraftforge.fml.loading.*` (Forge), `net.neoforged.fml.loading.*` (NeoForge), `cpw.mods.modlauncher.*` (Forge/NeoForge), and Sponge Mixin launch/service/transform packages. Class origin verification is **not** a demonstration that all final bytecode produced by a loader has been observed: Java Instrumentation is not a universal observer of third-party Mixin/ClassLoader changes. Transforms returned by a `MinecraftHook` remain checked against signed **plugin SHA-256 + exact binary class name**, with forbidden results terminating the JVM.

The optional signed `loaderClassBytes` list pins exact observed class-definition bytes for selected binary class names, at the agent's observation point **after bytes are handed to Java Instrumentation and before NeverLauncher's Trusted Java hooks run**. An unequal hash terminates the JVM. Example within the same signed policy JSON:

```json
"loaderClassBytes": [
  {"class":"net.minecraft.client.Minecraft","sha256":"<SHA-256 of class-definition bytecode observed on the selected build>"}
]
```

These hashes must be measured and approved for the exact Minecraft/loader/mod combination by an operator; they are **not** the SHA-256 of a class name or necessarily the untransformed `.class` from a vanilla JAR. Missing class entries are not pinned and class checks do not prove the result of subsequently registered third-party Java transformers. For `loaderClassBytes`, omitted means no per-class fingerprint enforcement; nonempty entries are validated by the signed Go/Rust policy verifiers and checked live in the Java agent.

This code does not disable loader transformations or grant broad exemptions for `-javaagent`, `-agentpath`, debugging or unapproved mods. The independently signed Guard policy and all existing pre-spawn checks remain mandatory.

## Operator instructions

1. Prepare and verify the exact Minecraft profile, runtime and loader libraries that the signed build references. The JVM source JARs for Fabric/Quilt/Forge/NeoForge, ModLauncher (Forge/NeoForge) and Mixin must be included individually. Determine the **actual class source JARs**, not just their dependency names. Do not guess hashes.
2. Add each library to the existing `artifacts` array in the policy payload, retaining the signed project, Minecraft version and loader:

   ```json
   {"kind":"loader-library","path":"libraries/net/fabricmc/fabric-loader/0.16.0/fabric-loader-0.16.0.jar","sha256":"<actual lowercase 64-character SHA-256>"}
   ```

   This path is illustrative only. Use the actual installed relative path, revision and SHA-256. Add ModLauncher/Mixin libraries where applicable; no wildcard or universal hash exemptions are available. Vanilla profiles must have no `loader-library` entries.
3. Increase the policy `epoch`, sign offline using the existing `cli/cmd/guard-policy-sign` tool and install via `guard-policy-install` with the external Ed25519 public key. Keep `LAUNCHER_GUARD_COMPAT_REQUIRED=1` and the trust key outside the client root. A policy from 0.50.3 that lacks loader-library entries **must be updated** before launching a guarded modded client; this is intentionally fail closed.
4. Start via the existing native Runtime or ClientFactory. On a denied launch, inspect stderr for `[Launcher Guard 0.50.4]` and verify the exact signed library paths. Do not disable the agent to bypass denial. Revocation of any pinned source digest prevents the next launch.

## Verified locally versus not certified

- `scripts/tests/guard_loader_0504.py` compiles real JAR files and executes Java 21 with a real `-javaagent` on synthetic loader marker classes. It tests all four loader families, Mixin, ModLauncher and negative cases. `go test` exercises the signed-policy/Trusted JVM integration and Guard loader list rules.
- A Rust compiler and Windows/macOS native runners are not available in the local environment. The 6-target CI workflow is provided but was **not executed** as part of this source patch.
- A full real Minecraft client, official login, server join, real upstream loader transformation pipeline, full Windows Sensor and independent signed-installer acceptance are **not** tested here. These remain `BLOCKED`; there is no claim of `0.50.4 GA` or of complete mediation of third-party Java bytecode changes.
- A trusted plugin has full JVM privileges, including Instrumentation and reflection. In-process CodeSource checking is not a security boundary against fully trusted malicious Java code or arbitrary native agents; such code must not be installed. Operational revocation while a game is already running is outside this release.

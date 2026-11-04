# NeverLauncher 0.50.2 — signed Guard compatibility policy

This release contains **launch-time enforcement**, not an attestation that every running class transformation is safe. The policy must be signed by a key outside the client directory; none of the commands below requires a private signing key on a player's machine.

## Authorize code for one game build

The exact signed scope is `projectId` + Minecraft version + loader. For ClientFactory legacy projects, `projectId` is the verified InstallPlan's `reproducibilitySha256`; for Rust Runtime it is the verified game manifest's `projectId`. A policy for one scope cannot authorize another one. `epoch` increases with *every* policy update or revocation; validity is at most 90 days.

1. Generate an offline keypair on an operator-controlled host, then protect the private key. Run from `cli/`:

   ```sh
   go run ./cmd/guard-policy-sign -mode keygen -private-key /secure/guard-private.hex -public-key /secure/guard-public.hex
   ```

2. Produce a reviewed UTF-8 JSON policy. Use actual SHA-256 hashes of **installed bytes**, paths relative to the game root, and the correct project scope. The sample values below must be replaced; they are not pre-authorized defaults:

   ```json
   {
     "schemaVersion": "launcher.guard-compatibility.v1",
     "projectId": "INSTALL_PLAN_REPRODUCIBILITY_SHA256_OR_MANIFEST_PROJECT_ID",
     "minecraft": "1.20.1",
     "loader": "fabric",
     "epoch": 1,
     "issuedAt": 1793664000,
     "expiresAt": 1793750400,
     "artifacts": [
       {"kind":"mod", "path":"mods/example.jar", "sha256":"REPLACE_WITH_64_LOWERCASE_HEX"},
       {"kind":"java-agent", "path":".launcher/trusted-jvm/releases/PACKAGE_SHA256/agent.jar", "sha256":"REPLACE_WITH_64_LOWERCASE_HEX"},
       {"kind":"java-plugin", "path":".launcher/trusted-jvm/releases/PACKAGE_SHA256/plugins/example.jar", "sha256":"REPLACE_WITH_64_LOWERCASE_HEX"},
       {"kind":"native-library", "path":"natives/linux/libexample.so", "sha256":"REPLACE_WITH_64_LOWERCASE_HEX"}
     ],
     "transformations": [
       {"id":"net.minecraft.client.Minecraft", "ownerSha256":"REPLACE_WITH_APPROVED_JAVA_PLUGIN_SHA256"}
     ],
     "revokedDigests": [],
     "revokedTransformations": []
   }
   ```

   Transformation `id` is the **exact binary class name** and `ownerSha256` is the pinned trusted Java plugin JAR digest (not the agent digest). Other class transformations in trusted hook callbacks are denied. Normal Fabric/Forge/Quilt loader internals are not automatically granted Trusted Java plugin permissions. The signed policy is authoritative only for the listed kinds, and unknown `.jar` files in `mods/` and native libraries in `natives/` are denied. Other game files continue to be verified by the existing signed InstallPlan/Manifest.

3. Sign off-device; never place `guard-private.hex` inside the client root:

   ```sh
   go run ./cmd/guard-policy-sign -mode sign -policy reviewed.json -private-key /secure/guard-private.hex -out signed-guard.json
   ```

4. Distribute the **public** key through an operator-managed trusted channel, separate from the client payload. On the client, set:

   ```sh
   export LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE=/operator-trusted/guard-public.hex
   export LAUNCHER_GUARD_COMPAT_REQUIRED=1
   launcher runtime client-factory guard-policy-install --client-dir /games/my-client --policy signed-guard.json --public-key /operator-trusted/guard-public.hex
   launcher runtime client-factory guard-policy-verify --client-dir /games/my-client --public-key /operator-trusted/guard-public.hex
   ```

   `guard-policy-install` persistently raises its epoch/digest/root watermark, then atomically saves the verified active policy. Re-installing the same signed bytes is idempotent. Changing content at the same epoch, an older epoch, changed root, expired policy or revoked code is blocked. An interrupted install may block launch until an operator clears a stale `.install-lock` after inspection and completes the same or newer valid installation.

## Enforcement and revocation

- Before ClientFactory `legacy-run` spawns the JVM, all explicitly allowed JAR/native payloads are SHA-256 verified; the checked code locations must match signed paths. All actual compat and Trusted Java agents/plugins are required in the allowlist. Unknown executable entries in `mods/`/`natives/`, symlinks, changed bytes and Java agent injection through inherited Java options cause launch rejection.
- Rust Runtime performs corresponding scope, digest, revocation, agent and controlled-directory checks before the Minecraft process starts. The Windows Guard Sensor no longer makes a blanket exception: it permits an argument `-javaagent:` only when it matches a nonrevoked, verified signed policy entry. Debugger/`-agentlib`/`-agentpath`/environment injection remain forbidden.
- The Trusted Java `premain` verifies plugin JAR digests and, when the policy is active, limits its `MinecraftHook.transformMinecraftClass` callbacks to exact `(plugin SHA-256, class name)` pairs. A forbidden attempted modification terminates the JVM. This does **not** sandbox fully trusted third-party code, which can use reflection or its own Instrumentation APIs.
- To revoke a JAR or transform, publish a **new signed epoch** listing the SHA-256 in `revokedDigests` or the class ID in `revokedTransformations`. Revocation is checked before subsequent launches. Existing live game sessions are not asynchronously terminated; that is a future continuous Guard/server-policy milestone.

## Trust/acceptance limits

The client-side watermark is stored under `.launcher/guard/accepted.json`. A user with full control over their OS account can delete/replace local files and environment variables. Require the policy from a deployment-owned supervisor/installer, protect the pinned public key and enable server-side proof of policy epoch in a future Server-Bound Guard release. A user-mode client cannot turn local anti-rollback state into a remote hardware trust anchor. Do not claim that this file by itself prevents a hostile player from altering their own machine.

The local Go tests exercise actual Ed25519 signatures, hash enforcement, tampering, expiry, revocation, rollback, symlinks and a **real spawned Java process** with permitted and forbidden class transformations. Six-platform Rust/Guard Sensor builds, actual modded Minecraft joins, release signing and independent installation receipts are mandatory external acceptance work. `0.50.2` remains **GA BLOCKED** until that evidence exists.

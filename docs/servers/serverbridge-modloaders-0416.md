# NeverLauncher 0.41.6 — Fabric, Quilt, Forge, NeoForge, Vanilla, Sponge

## Executable changes

* Fabric/Quilt and Forge/NeoForge now read the authoritative Java game-server whitelist and profile-ban collections **after** dispatch. Where a target API does not expose a readable state, they return `executed` (never a fabricated `succeeded`). An observed mismatch returns `failed`.
* Each of these four adapters registers the exact player UUID with `KickConfirmations` **before** invoking the real platform disconnect method. Only the native disconnect callback for the same name and UUID proves `player.kick`; on timeout, shutdown, or missing UUID the response remains `executed`/`indeterminate`. A concurrently pending kick on the same username does not trigger a second disconnect.
* Routing-mode commands read back the local, live admission flags; asynchronous JVM stop is `accepted`, not completed.
* Sponge now correlates kicks with its native `ServerSideConnectionEvent.Disconnect`, verifies whitelist mode only when the state is readable, and does not hide broadcast partial delivery. It still returns `unsupported` for whitelist-entry/ban/save/console actions that its universal SpongeAPI adapter does not implement; those operations have **not** been advertised as newly supported.
* The Vanilla sidecar issues real RCON commands, follows whitelist and ban changes with `whitelist list` / `banlist players`, and proves membership only when Mojang's English count and full list are self-consistent. Non-English/ambiguous/truncated responses remain `executed`. Stop is `accepted`. Vanilla cannot authenticate players through a plugin or prove a kick from a UUID-bound game API.
* `BridgeControlResult` remains the signed ServerBridge control response, with `succeeded` evidence checked by the existing Backend 0.41.5 logic; no parallel command path or fake production endpoints were added.

## Locally executed verification

```
e2e/scripts/test-serverbridge-control-0416.sh
python3 e2e/scripts/test-bukkit-control-0415.py
```

The first command compiles all production Java 21 source files from `plugins/bridge-common` and `plugins/vanilla-bridge`, then runs readback, exact UUID event-matching and real localhost TCP-RCON tests. The second is the preexisting Bukkit family regression suite. These are not substitutes for testing against upstream game-server JARs.

## Live certification still required

On hosts with the actual upstream server distributions and Gradle dependencies, build each module and deploy the output JARs against each declared Minecraft/loader/SpongeAPI target. Test whitelist/ban state before and after changes, kick with a real player and native disconnect event, player reconnect, failed console commands, routing modes, plugin stop during pending control, and shutdown while the Backend is unavailable. Test Vanilla with a real dedicated server configured with a protected loopback RCON port and a live backend identity. Never mark a missing loader/server JAR as PASS or use a simulated API outcome as proof of upstream compatibility.

**Status:** Java 21 common + Vanilla integration and local TCP-RCON passed; authentic Fabric, Quilt, Forge, NeoForge, Vanilla Minecraft, Sponge server-JAR runs and full Backend/PostgreSQL E2E are **not certified** by this patch environment.

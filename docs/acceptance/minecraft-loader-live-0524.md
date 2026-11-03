# NeverLauncher 0.52.4 — Minecraft/Loader native multiplayer compatibility

This is an **executable runtime gate**, not a declaration that any of the 280 required targets passed. The existing compatibility matrix runs a real client with its required OS/CPU/JDK/loader. As of 0.52.4, every ordinary `client` target **also needs evidence of an actual join** to an exact-version dedicated Minecraft server, while the five existing Vanilla matching-server targets and five end-to-end integration targets keep their separate deeper scenarios.

## Provision verified server binaries

The gate uses the pre-existing pinned actual server execution in `staged_matching_0344.MatchingServer`, with a dedicated isolated server on `127.0.0.1`. For Vanilla it retrieves and SHA-256 verifies the authoritative server through `nl runtime vanilla-server`. Where upstream does not provide a server for an old Minecraft version, and for **all modded loaders**, the operator must provide a complete tested server distribution ZIP, a SHA-256 and an explicit matching resolved loader version. A zipped directory must contain its entrypoint at the archive root: Fabric/Quilt usually `server.jar`, Forge/NeoForge commonly `run.sh` or `run.bat` (or specify `serverEntry`). For supported modded servers this compatibility check does not require the separate ServerBridge plugin: ServerBridge has its own 14-target live matrix.

Supply `LAUNCHER_E2E_SERVER_PINS=/absolute/path/pins.json` and `LAUNCHER_E2E_SERVER_BUNDLE_DIR=/absolute/path/zips`. GitHub Actions reads the same two values from repository variables `LAUNCHER_E2E_SERVER_PINS_PATH` and `LAUNCHER_E2E_SERVER_BUNDLE_DIR`; on hosted runners the files must be provisioned by the operator (e.g. an independently verified artifact repository/cache) before the task starts. Missing cache, signature material, installed JDK, desktop graphics or server binary is **BLOCKED**, never a successful test. Do not put credentials or sensitive world data in these assets.

The pins file must contain `schema: neverlauncher.compatibility-server/0.52.4` and an object `targets` keyed by the **exact matrix target ID**. Each entry must contain `minecraft`, `loader`, `loaderVersion` (fully resolved, never `latest`), `file` (simple ZIP basename), `sha256` (lowercase 64-character digest) and optional `serverEntry` (simple root filename). Vanilla with a Mojang-published, verifiable server does not require this file. The helper refuses symlinks, path traversal, hash mismatches, inappropriate OS scripts, missing metadata and unexpected server/loader versions. This is operator-owned trusted executable code: run only on disposable, isolated runners.

## Actual execution

1. The stock E2E script materializes and verifies the Mojang client or exact loader; its pinned resolution lock and classpath are checked. Java identity (major/vendor/executable SHA-256) and native OS/arch are verified by the compatibility runner.
2. The live coordinator launches the **real dedicated Minecraft JVM** using a verified server JAR or pinned server distribution, verifies boot, exact Minecraft version and resolved loader version (when applicable), and proves authenticated localhost RCON gameplay ticks.
3. The real Runtime launches the materialized client with `--server 127.0.0.1 --server-port <ephemeral>` (or Quick Play on modern versions). The client must actually connect; running at the title screen or timing out without a join does not pass.
4. While the client is connected, the coordinator observes the true player name in the server join log **and** RCON `list` (twice) while the world's tick counter advances. After the client returns the coordinator invokes the real server `stop` command over RCON, requires successful JVM exit, and hashes its **final** console log and client certificate. The readiness, online-player witness and clean-shutdown receipts are also bound to the originating commit, CI run and attempt.
5. The compatibility runner checks `live-join.json`, `live-server-ready.json`, `live-server-witness.json`, `matching-server.log`, the pinned server identity, client certificate and hashes. The matrix aggregator and acceptance inventory independently recheck those same original files. Tainted, reused, mismatched or missing evidence results in FAIL/BLOCKED.

### Execute one target on a native host

Set the standard environment variables already used in `.github/workflows/compatibility.yml` (`LAUNCHER_COMPAT_TARGET_ID`, `LAUNCHER_COMPAT_OS`, `LAUNCHER_COMPAT_ARCH`, `LAUNCHER_COMPAT_SCOPE=client`, `LAUNCHER_E2E_MINECRAFT_VERSION`, `LAUNCHER_E2E_LOADER`, `LAUNCHER_E2E_LOADER_VERSION`, `LAUNCHER_E2E_JAVA_MAJOR`, `LAUNCHER_E2E_JAVA`), provide pins as above for loader targets, and run:

```bash
bash e2e/scripts/run-compatibility-case.sh
```

On Linux the real GUI requires Mesa/OpenGL and Xvfb; on Windows/macOS it must run in a logged-in GUI session with the required hardware/graphics capabilities. CI uses up to 90 seconds for the client scope. Official Microsoft account authorization, release-installer signing and verified final-package distribution are separate 0.53.0 gates: this localhost compatibility scenario uses only an isolated offline-mode test player and cannot certify production authentication.

**Gate status:** no 280-target native Minecraft matrix, pinned loader server distributions, account logins or external final-package receipts were run while authoring 0.52.4. A green unit test is not a game launch; 0.53.0 GA remains BLOCKED.

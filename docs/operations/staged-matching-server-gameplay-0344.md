# Launcher 0.34.4: actual matching-server and gameplay verification

This implementation **executes** the exact signed staged client already installed
by 0.34.2, not a Client Factory rebuild or an invented test package. The
0.34.3 menu/loader startup probe runs first. A **second normal Runtime
launch** connects that same installation to a real local Minecraft dedicated
server via `--matching-server-port`. The launched Java PID is observed from X11,
not inferred from a CI-generated `joined the game` JSON field.

## Isolated server provisioning

* Vanilla: `nl runtime vanilla-server --minecraft <signed version>` downloads
  the Mojang distribution and verifies the Mojang SHA-1/derived SHA-256. The
  staged runner re-hashes `server.jar` after installation and requires a matching
  boot-version log before accepting it.
* Fabric, Quilt, Forge and NeoForge: a **complete server distribution ZIP** must
  be provided from protected runner configuration with an independently pinned
  SHA-256 (`NL_MATCHING_SERVER_BUNDLE_URL`, `NL_MATCHING_SERVER_BUNDLE_SHA256`).
  Server `server.jar` (Fabric/Quilt) or `run.sh` (Forge/NeoForge) is started from
  an isolated extracted root. The loader and exact version must be visible in
  the server boot output. Missing version, jar or loader is a failure, not a
  fallback to Vanilla.
* Modded servers require a ServerBridge mod JAR inside `mods/` with independently
  pinned SHA-256 (`NL_MATCHING_BRIDGE_PATH`, `NL_MATCHING_BRIDGE_SHA256`) and
  expected version (`NL_MATCHING_BRIDGE_VERSION`). The plugin must positively
  report its startup and version in the actual server log. If the bridge cannot
  connect to the required backend for its login policy, the join fails; this
  runner never bypasses its authentication policy.
* A bundled server is accepted **only** when the complete ZIP hash matches,
  safe paths have been checked and the entry point is present. No build or
  loader installer is invoked in place of the pinned bundle.

The runner writes a fresh `server.properties` with loopback-only server and
RCON, ephemeral ports, a random RCON password, EULA and a temporary flat creative
world; the server process tree is terminated after each run. Never expose the
RCON password in artifacts. These local offline server settings are **not**
equivalent to real custom/official authentication validation (V07).

## Positive checks

1. The real dedicated server logs the exact Minecraft version, matching
   loader/version and, when required, ServerBridge identity/version; it finishes
   preparing the world and answers an authenticated RCON `time query gametime`.
2. The real Runtime client auto-enters `127.0.0.1:<ephemeral port>` using
   Minecraft's ordinary `--server/--port` or `--quickPlayMultiplayer` mechanism.
   The signed manifest, materialized client files and pinned release key are
   unchanged from startup validation.
3. A **fresh** client connection log exists; the server logs the named player's
   join and RCON `list` returns the same online player. The window's X11 process
   belongs to the launched Java subprocess with the exact selected Java binary.
4. The runner captures a real rendered world frame and reads the player's NBT
   `Pos` and the world's game ticks from the running server. It focuses that
   exact Java window, sends the normal `W` key via X11 and releases it.
5. New game ticks and a nonzero **server-observed** player-position change are
   mandatory, together with a changed rendered frame and absence of late JVM,
   Guard, loader or server crash. Teleport commands or fabricated player state
   never count as the client's action.

Stages in the existing PostgreSQL-backed staged-run report are `server-readiness`,
`matching-server` and `gameplay-smoke`, in addition to previous
`manifest-files`, `materialization`, `startup` and `loader-readiness`. Every
stage has an independent result. Diagnostics include server boot log, immutable
server artifact SHA, join log presence, the PID-bound world screenshots and their
SHA-256, game tick observations, player state snapshots and the Runtime
launch result. The backend stores only stage summaries / SHA-256 references,
while CI preserves detailed artifacts. Grant credentials and RCON passwords are
excluded.

## Intentional limits

This target requires an actual compatible server distribution, initialized
ServerBridge and a Linux X11 GUI-capable runner with `xdotool`, `scrot`,
`identify`, `xwininfo`, `xprop`, `glxinfo` and Tesseract. Other graphics
platforms remain out of scope of this target. Supported gameplay mode is an
offline-enabled signed profile and isolated offline server; profiles that need
real provider credentials are **blocked**, not certified via a mock login.

These results are **observational, not trusted release attestation**. The
fail-closed 0.34.1 stable gate remains enforced; later V04–V06 will establish
runner trust, evidence binding and freshness.

## Verification

```sh
python3 e2e/scripts/test_staged_matching_0344.py -v
python3 e2e/scripts/test_run_staged_package_0342.py -v
python3 e2e/scripts/test_staged_readiness_0343.py -v
# With Go 1.27.3 and module dependencies available:
cd services/api && go test ./internal/httpapi -run 'TestMatchingStagedReportObservations0344' -count=1
# Actual Minecraft GUI run: workflow staged-package-runtime-0342.yml,
# protected runtime-validation-staging environment, real staged package ID.
```

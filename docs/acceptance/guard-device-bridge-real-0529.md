# NeverLauncher 0.52.9 — Guard / Device Trust / ServerBridge

## What executes

The API's `guard_shadow_05012.go` now writes the actual running `Server.Version` instead of the stale `0.50.12`. A real Go-produced chained HMAC journal is read by `adversarial_pilot_05012.py`; modification or replay invalidates it. No player names or session tokens are logged. A single malformed version or a reused journal from a different release fails closed. The existing signed/revoked Guard-binding checks are not bypassed.

The Vanilla production sidecar now **requires one successful signed Backend heartbeat before publishing `server.ready`**. `scripts/acceptance/vanilla_sidecar_live_0529.py` actively connects to the *running* dedicated Minecraft 1.21.1 server over the local status socket and RCON, validates the real sidecar JVM PID and exact JAR hash, checks original Vanilla logs and measures advancing game ticks. RCON password is read from `LAUNCHER_VANILLA_RCON_PASSWORD` **only**; it is never stored in the result. Run on the host with Linux `/proc`, an already deployed and signed release sidecar and a private RCON port. An offline Java simulator is not accepted as a live server.

The 14 target IDs have different declared capabilities:

- 10 runtime-E2E: Velocity, BungeeCord, Waterfall, Spigot, Paper, Purpur, Folia, Fabric, Forge, NeoForge. Original per-server Docker process, exact deployed JAR, signed heartbeat, real network allow-then-revoke, server logs and Paper client join are rechecked by `serverbridge/live_matrix_04113.py`.
- 3 build-compatibility: Bukkit, Quilt, Sponge. Production-built JARs are validated by `serverbridge/certify_release.py` (14-JAR cohort and executable adapter capability harness). **This does not make those three targets live certified.** For a 14/14 *live* claim, add native upstream Bukkit/Quilt/Sponge E2E evidence; this milestone does not claim to have performed it.
- 1 sidecar-RCON-E2E: Vanilla, with actual status socket, authenticated RCON, Java process, startup handshake and ticking server.

For Device Trust, the verifier consumes and rechecks **all seven original per-target results** from the existing matrix and hashes the actual evidence files; a JSON PASS without its underlying logs cannot pass. Native/headless CI does not prove hardware-backed secure storage. Guard additionally requires original packages and binaries for all three CI targets, six separate native JVM adversarial records, protected server-HMAC shadow journals, independently reviewed revocations, real authenticated Minecraft join evidence and actual matched frame-time measurements. A false positive, inconclusive or unreviewed revocation blocks the live gate. The proposed shadow sample of 10,000 legitimate player-hours requires **independent verification**, not simply timestamps in a journal.

## Local execution

```bash
python3 -m unittest discover -s scripts/acceptance -p 'test_guard_device_bridge_real_0529.py' -v
python3 -m unittest discover -s scripts/acceptance -p 'test_guard_shadow_crosslang_0529.py' -v
bash e2e/scripts/run-serverbridge-adapter-capabilities-0286.sh
python3 scripts/guard_ci/test_adversarial_pilot_05012.py
python3 scripts/acceptance/guard_device_bridge_real_0529.py local \
  --only-suite loader-transformations --output /absolute/private/0529-loader-only.json
```

`local` with `--only-suite` intentionally returns `LOCAL_PARTIAL_JVM_REGRESSIONS_NOT_GA`. Run without `--only-suite` on a suitable native Linux JDK 21 host for the full four-suite locally runnable Guard process checks. These are real Java child-process tests, **not official Minecraft gameplay or physical/native signing certification**. Regressions with simulated RCON servers are only hostile input tests.

## External live execution

Run existing physical CI/natively signed candidate workflows; preserve **the original** seven Device Trust results and logs, three Guard CI results **and binaries/packages**, six native adversarial JVM reports and logs, game session evidence and original serverbridge runtime tree with ten live Docker processes. Build the 14 real production ServerBridge JARs using the project release pipeline and verify every SHA-256. Provision a genuinely running Vanilla server and signed sidecar as above. Configure private server shadow journaling **before** executing player sessions, retain its 0600 HMAC key outside results, obtain independent incident reviews, matched frame-time capture and real authorized player join data.

On a dedicated machine create a mode-0600 JSON configuration at `/etc/neverlauncher/acceptance/guard-device-bridge-0529.json`. It must contain exactly `sourceCommit`, `runId`, `repository`, `deviceResults`, `guardResults`, `guardJvmResults`, `guardShadowDir`, `guardShadowKeyFile`, `guardIncidentReviews`, `frameBaseline`, `frameGuard`, `gameRuntime`, `gameServerLog`, `player`, `serverbridgeRuntime`, and `vanilla`. All paths are absolute. The `vanilla` object contains exactly `sidecarPid`, `sidecarJar`, `sidecarSha256`, `sidecarLog`, `serverLog`, `serverDir`, `minecraftPort`, `rconPort`, `minecraftVersion`. No password or access token is included in JSON.

```bash
export LAUNCHER_VANILLA_RCON_PASSWORD="$(cat /secure/rcon-password)"
umask 077
python3 scripts/acceptance/guard_device_bridge_real_0529.py live \
  --config /etc/neverlauncher/acceptance/guard-device-bridge-0529.json \
  --output /absolute/new-private/guard-device-bridge-result.json
```

The script does not simulate missing machines, invent status reports or relax any required acceptance row. It emits `LIVE_CHECKS_PASSED_REVIEW_REQUIRED` **only after original evidence and the active Vanilla probe pass**. This is not production GA: six signed final package verification, independent proof of actual hardware secure storage, independent review of player hours/false positives and required live Bukkit/Quilt/Sponge upstream runs remain separate gates. Never expose RCON passwords, unredacted player data, shadow HMAC keys or raw journals in public CI artifacts.

## Limitations of this development environment

Local Go standard-library journal tests and Go→Python authenticated chain replay, Java capability harness, and negative socket checks can run here. They cannot establish hardware Guard capabilities, gameplay false-positive rates, running upstream Minecraft adapter compatibility, actual Device Trust key protection, signing, or six-platform native installations. Any missing external prerequisites are `BLOCKED`, not `PASS`.

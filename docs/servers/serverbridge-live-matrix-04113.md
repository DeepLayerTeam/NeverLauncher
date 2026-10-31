# 0.41.13 — ServerBridge live compatibility certification

The test driver is executable, not a list of API or compatibility claims.

```bash
# Requires Docker Compose, upstream images and live JVM/network access,
# PostgreSQL, Go, Gradle, Cargo, Maven, Java 21 and graphical test prerequisites.
bash scripts/test/serverbridge-live-matrix-04113.sh --core
# Strict GA gate. It fails until all 14 targets have independent live evidence.
bash scripts/test/serverbridge-live-matrix-04113.sh --all
```

The real E2E runner builds production bridge JARs, starts production Minecraft
and proxy Docker images, checks Bridge heartbeat and node readiness, performs
real Minecraft login probes and verifies session revocation. Paper requires a
real launched Mojang client JVM and server join. For **each live service**, the
0.41.13 recorder additionally interrogates Docker for the running container,
immutable image ID, exactly one live JVM process, JVM major version >= 21,
health status and unmodified platform logs. The verifier checks the SHA-256 of
network probes and server logs, expected node ID/port, ordered login and revoked
login markers, and Paper's genuine player-join log. It does not accept a bare
`status: passed` or declarations of compatibility as live evidence.

## Explicit coverage boundary

The existing full server E2E contains ten runtime instances:
Velocity, BungeeCord, Waterfall, Spigot, Paper, Purpur, Folia, Fabric, Forge,
and NeoForge. `--core` confirms only these ten when a real Docker test has
passed and emits `core-passed-not-full-matrix` rather than `passed` for the full
14-target matrix. **Bukkit (shared runtime without independent dedicated-server
run), Quilt, Sponge, and Vanilla/sidecar have no equivalent live, server-side
proof in this E2E.** Existing build, client-only or protocol-simulation tests
must NOT be substituted for a live Minecraft/JVM/Proxy test. `--all` fails
closed with `not-certified` for missing coverage; certification of the whole
0.41.13 compatibility scope is pending real upstream tests for those targets.

The host executing this test must provide network access to upstream runtime
artifacts; do not use an API stub, a synthetic JVM or prerecorded positive
certificates. Runtime evidence is written to `e2e/runtime/` and should be
retained with the exact source commit and artifact hashes. Private E2E
credentials in runtime files must not be uploaded as public artifacts.

The offline verifier regressions are intentionally separate from live game
certification:

```bash
python3 -m unittest discover -s serverbridge/tests -p '*04113.py' -v
bash -n e2e/scripts/run-minecraft-e2e.sh
```

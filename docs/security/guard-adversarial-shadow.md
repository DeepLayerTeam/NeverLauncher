# NeverLauncher 0.50.12 — Adversarial E2E & Shadow Pilot

**Status: source implementation with live Java/Go regression checks, not a certified Guard/Minecraft rollout.** This milestone adds an executable test runner and authentic server-observation journal. Nothing in the repository pre-populates 10,000 player-hours or claims fake Minecraft joins.

## Live server observations (not disabled enforcement)

In the control-plane API service environment:

```sh
install -d -m 0700 /var/lib/launcher/guard-shadow
openssl rand -hex 32 > /etc/launcher/guard-shadow-key.hex
chmod 0600 /etc/launcher/guard-shadow-key.hex
export LAUNCHER_GUARD_SHADOW_DIR=/var/lib/launcher/guard-shadow
export LAUNCHER_GUARD_SHADOW_KEY_FILE=/etc/launcher/guard-shadow-key.hex
```

Both variables must be set; absent variables disable the recorder, mismatched variables or inaccessible/unsafe key/directory fail closed when the authoritative Guard session is checked. The reader must be an operator with OS access to the private key and journal. Never ship or expose that key to Admin/Desktop or the game client. Journal files are private (0600), per-process and append-only. Each observation is HMAC-SHA256 authenticated, linked to the previous per-process observation, and has a monotonic sequence. The server records no username, UUID, raw session correlation ID, IP address, Minecraft token, device identifier or JVM memory dump. Session/node pseudonyms are HMAC-derived from the server-only key. Rotating this key separates cohorts; an external recorder must keep the previous key secured to verify its cohort.

`allowed` is written **after** the signed ServerBridge heartbeat drives a successful PostgreSQL session check. `revoked` is written only after successful invalidation of that exact session and enqueue of the existing correlated `player.kick`. This is *observation of the existing enforcement path*; it does not disable necessary security decisions and does not certify new detectors without a separate pilot. A server heartbeat is not a fresh client-memory measurement.

```sh
python3 scripts/guard_ci/adversarial_pilot_05012.py analyze-shadow \
  --journal-dir /var/lib/launcher/guard-shadow \
  --key-file /etc/launcher/guard-shadow-key.hex \
  --reviews /private/guard-incident-review.jsonl \
  --output /private/shadow-result-05012.json
```

Optional manual reviews are JSONL with exactly `eventMac`, `verdict` (`true_positive`, `false_positive`, `inconclusive`), `reviewerId` (nonsecret reference). Every real revoke requires a review. A candidate without review, a false positive or inconclusive review keeps the gate blocked. Reviews are operator assertions, not signed independent adjudication; do not treat them as independently proven. Keep the review history and restricted original evidence separately. **Only intervals bounded by two actual successful server verifications within 30 seconds count** towards the conservative `observedGuardActiveHoursLowerBound`. These are not certified player-hours; independent real-player evidence is required. A journal HMAC prevents undetected edits/reordering to retained records but cannot prove that a privileged operator did not delete an entire journal or truncate its final records. Archive periodic signed receipts and independent checks for GA.

Retain full private raw evidence only for an approved investigation period (initial operational suggestion: 30 days). Limit access to approved incident responders; publish aggregate counts and redacted samples only.

## Run real adversarial JVM processes

```sh
python3 scripts/guard_ci/test_adversarial_pilot_05012.py
python3 scripts/guard_ci/adversarial_pilot_05012.py run-jvm --output /private/guard-adversarial-05012.json
```

The runner executes the production Java Agent against actual Java child processes for loader provenance, unauthorized or modified classpath/mods, native ELF, the continuous JVM watchdog, and Linux process restrictions. Raw test stdout is stored privately; the report includes duration, exit code, test count, log SHA-256 and scenario status. Absent executables, missing tests, skipped mandatory tests and timeouts are not `PASS`. Linux native probe requires GCC and a configured Java toolchain. The CI workflow runs these scenarios on six OS/CPU targets. A real JVM fixture is **not** a real Minecraft client nor proof of anti-cheat efficacy against arbitrary privileged code.

For additional native Windows/Rust sensor adversarial checks use the existing `scripts/guard_ci/windows_adversarial.py` and the per-OS Guard CI workflows; missing Rust/Windows execution is `BLOCKED` for final certification.

## Real Minecraft and gameplay evidence

Run the repository's existing `e2e/scripts/run-minecraft-e2e.sh` with the authorized Minecraft account, real upstream files, backend, PostgreSQL, signed published package and Paper/loader server. Retain its complete output directory, original Paper server log and exact release commit. Then verify:

```sh
python3 scripts/guard_ci/adversarial_pilot_05012.py verify-game \
  --work /private/live-minecraft-runtime --paper-log /private/paper-live.log \
  --username THE_AUTHORIZED_TEST_PLAYER \
  --output /private/real-game-05012.json
```

This command checks the actual Mojang-client `result.json` assertions, signed release and package checks, mandatory evidence file existence and SHA-256, the runtime launch result, and both authenticated server admission and Paper's *real* `joined the game` log line for the designated test player. Usernames are not included in the resulting public report. It does not certify gameplay duration, Guard's inaccessible host sensors, or an independent operator's identity. False/missing evidence refuses the run. The unit test only checks this verifier with generated fixtures; it is not a genuine game join.

## Actual game-frame performance

Record identical scenes with Guard off/on on identical hardware, JVM, Minecraft version, loader, game build and graphics settings. Export genuine per-frame times (`frameTimeMs`) from PresentMon, MangoHud, CapFrameX or the other named supported profilers, at least 600 frames per capture. Each capture folder contains `frames.csv` and `capture.json` with `os`, `arch`, `cpu`, `gpu`, `minecraftVersion`, `loader`, `scene`, `buildSha256`, `sourceTool`. The two `capture.json` files must match exactly. The engine computes empirical interpolated p95 and the relative regression; the roadmap's suggested initial target is no worse than 3%.

```sh
python3 scripts/guard_ci/adversarial_pilot_05012.py compare-frame-times \
  --baseline /private/frames/guard-off --guard /private/frames/guard-on \
  --output /private/guard-performance-05012.json
```

The code refuses missing/mismatched metadata, fewer than 600 frames, invalid values and implausibly small/huge frame times. It does **not** generate synthetic gameplay FPS. Frame capture provenance remains operator-asserted until the independent reviewer verifies raw captures, profiler version, benchmark scene and source hashes. Measure startup and RSS separately; this report is p95 frame time only.

## Release gate remains blocked until real evidence exists

For 0.50.12/0.51.0 acceptance, require real Windows/Linux/macOS x64/ARM64 Guard binaries and authenticated ServerBridge heartbeats; actual Mojang client joins with Vanilla/Fabric/Quilt/Forge/NeoForge; authorized mods/agents; deliberate unauthorized tamper/instrumentation; supported OBS/overlays/AV/GPU scenarios; matched frame-time captures; independently reviewed false positives; at least 10,000 **independently verified legitimate player-hours**; external release signatures and a second reviewer for exact final packages. The code does not imply these occurred. No kernel driver or universal cheat-detection claim is introduced.

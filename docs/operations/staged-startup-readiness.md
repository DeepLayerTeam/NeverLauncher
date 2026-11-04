# 0.34.3: staged startup and loader readiness

The existing staged-package workflow now launches the **downloaded staged bytes**
via the normal Runtime `launch` command and observes the actual GUI process.
It does not rebuild Minecraft or use a mock runtime. It still produces **untrusted,
observational** evidence; stable publication remains blocked until V04–V06/V11.

## Linux GUI execution

The 0.34.3 probe supports an isolated Linux X11/Xvfb runner with a usable GLX
renderer, `xwininfo`, `xprop`, `glxinfo` (Mesa utilities), `scrot`, ImageMagick `identify`, and Tesseract
with English recognition data. The workflow installs these dependencies.
Windows/macOS/native Wayland require their own GUI observers (V10) and
return `blocked`, not a Minecraft compatibility failure.

A startup PASS requires all of the following from the *same Runtime run*:

- The normal runtime verifies the signed manifest and installed package, and
  starts the actual JVM. The X11 PID of the Minecraft window must belong to
  its process tree and execute the selected Java binary; a screenshot from another application cannot pass.
- At least two separate captures of that Minecraft window contain at least
  two recognizable **English** title-menu buttons (Singleplayer, Multiplayer,
  Options, Quit Game). Image entropy must exceed the minimum threshold.
- Rendered frames must differ and remain active until the end of observation
  (a 12-second liveness window rejects a frozen UI).
- If the manifest selects Fabric, Quilt, Forge or NeoForge, its corresponding
  loader bootstrap must be observed in the actual client log. Loader stage is
  reported separately. Vanilla has no external loader requirement.
- No JVM crash file, Minecraft crash report, OOM, fatal log/Guard violation,
  or unexpected JVM exit may occur during the run.

A mere PID, timeout, LWJGL marker, loader log or a stale screenshot never
passes. If positive menu evidence is unavailable before the configured time
limit, startup fails; absence of a functioning GUI probe is reported blocked.
Unsupported languages or visually modified menus may give a false negative;
this conservative detector must never be used to claim those clients are
incompatible with Minecraft. For such distributions, provide a dedicated
verified UI probe rather than weakening PASS criteria.

The worker writes `startup-readiness.json`, two frame images,
`runtime-launch.json`, plus existing staged execution / install evidence.
Only hashed observational stage results are posted to Backend. Restricted CI
artifacts must have the same access controls as other runtime diagnostics;
redaction/retention hardening remains V12. No signing key or delivery grant
is included in the diagnostic report.

The legacy Factory `certify-vanilla` and `certify-run` routes lack real GUI/menu
observation and now refuse to issue or accept positive startup certification
from only a successful JVM exit, a log marker or a timeout. Their old v1
certificate path is deliberately fail-closed until migrated to equivalent
positive readiness evidence. Do not use v1 certificates for promotion.

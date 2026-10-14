
## Upstream availability and CI certification (0.21.5)

The compatibility catalogue is not a guarantee that an upstream loader exists.
The 2026-10-14 upstream snapshot reports Quilt 1.14–1.14.3 absent from Quilt
Meta, and only prerelease NeoForge builds for Minecraft 1.20.3, 1.20.5,
1.21.2, 1.21.6, 1.21.7, 1.21.9, 26.1 and 26.1.1. These 12 entries remain
in `compatibility/targets.json` as `required: false`, with an explicit
`unavailableReason`. The public compatibility table lists **NOT CERTIFIED**,
never PASS, and the CI plan does not start those unsupported combinations.
Re-enable individual rows only after confirming official stable upstream
availability and adding a real successful certification result.

Windows actual-client certification requires a modern OpenGL context. On the
GitHub-hosted Windows runners the CI script downloads the architecture-specific
Mesa llvmpipe build, checks the pinned release SHA-256 and PE architecture, and
installs `opengl32.dll` next to the **disposable CI JDK**. This does not bypass
NeverGuard, suppress a Minecraft crash or certify an unexecuted client.
Cross-platform Windows results remain mandatory and fail closed.

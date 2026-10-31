# NeverLauncher 0.26.9 — Minecraft Java online/offline launch

## Execution paths

The Desktop launch selector provides three **mutually exclusive** realms. It
sends `authMode` to the Rust launch command; Rust rejects inconsistent
credentials before starting the protected Java process.

- **Official Minecraft:** a previously authenticated Minecraft Java UUID and
  access token are retrieved from the **native credential vault**, verified by
  the native Minecraft Services client immediately before launch, then injected
  into the Minecraft Java process. The renderer receives only profile metadata.
  The launched game performs its own ordinary Mojang sessionserver `join` while
  negotiating an `online-mode=true` server connection. NeverLauncher does not
  forge a serverId, call `hasJoined` on the client's behalf, or route official
  traffic through a project Yggdrasil endpoint. Java 1.21.9+ and 26.x do not
  receive the removed `--userType` argument.
- **Project Yggdrasil:** the backend issues a project-bound Minecraft session.
  NeverRuntime validates the realm, requires a *required, signed* `authlib-injector`
  JAR present in the verified installation, and installs the agent before Java
  starts. Missing, optional, duplicated, or user-owned injector artifacts stop
  the launch. ServerBridge join tickets remain project-specific and cannot be
  used for an official account.
- **Offline:** an offline-capable signed Manifest and matching verified local
  cache are required. No online access token or UUID is reused. The client
  receives only an offline placeholder `0` for the game launch, not a Mojang
  credential. Offline auto-enter and ServerBridge IDs are prohibited. Offline
  launch never claims admission to an online-mode server.

The runtime removes old authentication arguments from resolved Mojang metadata
and manifest game args before inserting the selected identity once. Neither
`--accessToken=...` nor duplicated `--uuid`, `--userType`, or `--username`
can override the selected account. Game tokens are redacted from launch
previews. Online authlib-injector arguments cannot be set from project JVM
flags: the injector is derived from a signed, locally verified JAR.

## Real integration checks (required for GA)

1. Configure the first-party Microsoft application from 0.26.1–0.26.6 and
   sign in with a licensed Java Edition account. Verify the UUID in the native
   profile matches the account and the token is refreshed prior to starting.
2. Launch vanilla and modded game builds, connect to an unmodified online-mode
   server. Verify a real `join` challenge from the Minecraft Java client and a
   successful server-side `hasJoined` from Mojang's sessionserver. Confirm that
   multiplayer settings/family restrictions fail without downgrading to offline.
3. Repeat with project ServerBridge/Yggdrasil credentials and the signed
   injector, using an explicitly configured project Yggdrasil server.
4. Remove/disable the signed injector, swap provider tokens, spoof UUID and
   inject fake `--accessToken` arguments. Verify that launches are rejected.
5. Select offline in a profile without signed offline permission and attempt
   auto-enter; verify rejection. In an allowed signed offline profile, verify
   local single-player works and protected online-mode access is not presented
   as authenticated.
6. Verify the above on Windows/Linux/macOS with the production Guard
   process policy and hardware device trust. Test launch logs and crash reports
   for leaked bearer tokens.

The successful live-provider and server checks cannot be substituted with mocks
or unit tests. CI tests verify local code paths only. The first-party Microsoft
application approval and live `online-mode=true` certification remain external
release blockers until actually performed.

# 0.31.12 — macOS Signed App Sandbox helper

Native macOS isolated execution is **not** a general-purpose sandbox for every
extension package. This stage supports **self-contained, single-file Mach-O**
`backend` and `cli` targets on macOS x86-64 / Apple Silicon. Java callback
runtimes, scripts, bundled runtime files, universal Mach-O wrappers and other
unsupported layouts are denied; no transition to `trusted` occurs.

## Deployment

1. Build helper **on a Mac** with a trusted Developer ID Application certificate:

   ```sh
   export NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID='YOURTEAMID'
   export NEVERLAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY='Developer ID Application: Example (YOURTEAMID)'
   ./scripts/security/build-macos-sandbox-helper-03112.sh /opt/neverlauncher/libexec/NeverExtensionSandbox
   ```

2. Configure the API service with `NEVERLAUNCHER_MACOS_SANDBOX_HELPER` and
   `NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID`. The helper must remain in a trusted,
   non-group-writable directory. Never ship an unsigned fallback.
3. The server validates the helper's Developer ID chain, Team ID, strict code
   signature and minimal entitlement set. Missing/overprivileged/unsigned helpers
   cause an immediate refusal. The helper checks the actual sandbox in its own
   process **before** accepting the image.
4. The existing signed NeverExtension policy remains authoritative. Filesystem
   `shared:<name>`, HTTPS and secrets are accessed through existing scoped Host
   Protocol operations, never through new macOS entitlements.

## Isolation mechanism

- Parent transfers the exact installed Mach-O image over a private FD; verifies
  its Mach-O type/architecture; binds an SHA-256 digest to a bounded transfer.
- Entitled helper stores it inside **its own** App Sandbox container, creates a
  private scratch directory, then uses `posix_spawn`. The child inherits the
  parent's static App Sandbox; it receives neither network entitlements nor
  access to the Backend working directory. The extension SDK connects over a
  single inherited Unix socketpair FD (4). No TCP/loopback or general-purpose
  XPC service is made available to the child.
- Host API validates exact one-instance IPC identity, normal authorization,
  policy permissions, and child PID. Closed broker socket never falls back to
  plain loopback for an isolated macOS instance.
- `RLIMIT_AS` and `RLIMIT_CPU` apply per process; a deadline kills the managed
  process group. **macOS does not provide cgroup v2/Job Object-equivalent
  aggregate process count, CPU or memory limits with this design**. The
  `maxProcesses` policy is not an OS-enforced tree limit in 0.31.12, and a
  child that deliberately detaches a process group may evade lifetime cleanup,
  but must still inherit App Sandbox restrictions. This limitation must be
  validated and addressed in the next resource enforcement stage before claiming
  full H12 compatibility. No absolute user-mode anti-tamper guarantees.

## Mandatory macOS acceptance

Do not label this release fully production-certified until a signed helper has
been built and its child verified on actual macOS hardware, including:

- `codesign --verify --strict`, correct Team ID and only App Sandbox entitlement.
- A self-contained extension uses allowed Host Protocol operations; direct
  connections, file reads/writes outside container and host environment are denied.
- Child `exec`/`posix_spawn` retains App Sandbox. No direct host network fallback.
- Malformed image, wrong digest, unsupported target, wrong signature, missing
  App Sandbox, `sandbox_check` failure and invalid IPC all fail closed.
- Timeouts, crash cleanup and behavior of spawned/detached children are measured.

Apple documents inherited static sandboxes for child processes and recommends
XPC when process-level privilege separation is needed. This helper provides a
sandbox boundary but **does not claim XPC-level privilege separation**.

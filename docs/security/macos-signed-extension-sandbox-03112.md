# 0.31.12 — macOS Signed App Sandbox helper

Updated for 0.43.11: native macOS isolated execution is **not** a general-purpose sandbox for every
extension package. This stage supports **self-contained, single-file Mach-O**
`backend` and `cli` targets on macOS x86-64 / Apple Silicon. Java callback
runtimes, scripts, bundled runtime files, universal Mach-O wrappers and other
unsupported layouts are denied; no transition to `trusted` occurs.

## Deployment

1. Build helper **on a Mac** with a trusted Developer ID Application certificate:

   ```sh
   export LAUNCHER_MACOS_SANDBOX_TEAM_ID='YOURTEAMID'
   export LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY='Developer ID Application: Example (YOURTEAMID)'
   ./scripts/security/build-macos-sandbox-helper-03112.sh /opt/launcher/libexec/NeverExtensionSandbox
   ```

2. Configure the API service with `LAUNCHER_MACOS_SANDBOX_HELPER` and
   `LAUNCHER_MACOS_SANDBOX_TEAM_ID`. The helper must remain in a trusted,
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
- The signed helper is identified by a *fixed code-signing identifier*,
  Apple Team ID and Hardened Runtime, with a minimal App Sandbox entitlement.
  The executable and all path ancestors must be non-writable by other users.
- The helper checks the child's **actual** inherited App Sandbox via
  `sandbox_check(childPID, ...)` before reporting readiness; all unsupported
  policies and missing signatures fail closed.
- 0.43.11 supports **maxProcesses=1 only**. Descendants are monitored with
  libproc at 20 ms intervals and trigger termination. An additional FD owned
  by the backend provides a liveness watchdog even when the backend crashes.
  `RLIMIT_AS` and `RLIMIT_CPU` are inherited by the child. The deadline kills
  its process group; the helper checks for descendants even if they detach.
- **Process enumeration is detection, not a kernel-enforced hard cap.** A very
  short-lived or deliberately detached grandchild may evade a sampling interval.
  macOS has no equivalent of cgroup v2/Job Object in this unprivileged design,
  and aggregate descendant CPU/memory guarantees are not claimed. Where strict
  process-tree limits are mandatory, operators must use a different OS-level
  isolation mechanism rather than relabel this policy as fully certified.
  No absolute user-mode anti-tamper guarantees.

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

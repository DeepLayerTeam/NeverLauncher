# NeverLauncher 0.31.10 — Scoped Filesystem, Network & Secrets Brokers

This release extends the **enforced Linux x86-64** sandbox from 0.31.9. It does not create host-network interfaces or mount host shares inside an extension. All privileged operations pass through the existing token-authenticated Extension Host Protocol over the inherited Unix socketpair, with server-side signed-policy checks **plus** the already-existing revocable permission manager. Extension manifest fields cannot disable the namespace, seccomp or cgroup restrictions.

## Operator setup

Run API as a **dedicated unprivileged service user** with a delegated cgroup v2 subtree. Configure only the directories you intend to expose through the broker:

```sh
NEVERLAUNCHER_EXTENSION_SHARED_ROOTS_JSON='{"reports":"/srv/neverlauncher-extension-shares/reports"}'
```

Roots must be absolute pre-existing directories. Every path component must be a genuine directory (not a symlink); the root directory `/` is forbidden. The application fails closed for sandbox packages requesting an unmapped or invalid shared root, without falling back to `trusted`. Keep host secrets **outside** shared roots; the administrator mapping is trusted configuration, never package-controlled. The broker runs with the unprivileged API service's permissions.

## Signed manifest example

The package manifest remains covered by the existing Ed25519 package signature, version-bound permission grants, and owner-approval digest. At installation/upgrade, changing the sandbox policy or requested permissions requires explicit administrator confirmation (0.31.8).

```json
{
  "permissions": ["storage:read", "storage:write", "http:outbound", "secrets:read"],
  "sandbox": {
    "version": "1", "mode": "isolated",
    "filesystemRead": ["package", "shared:reports"],
    "filesystemWrite": ["scratch", "shared:reports"],
    "networkOutbound": ["api.example.com:443"],
    "secrets": ["api_token"],
    "maxProcesses": 4, "maxMemoryBytes": 134217728,
    "maxCpuPercent": 25, "timeoutSeconds": 30
  }
}
```

A manifest request alone never grants access. The operator must approve the separate `storage:read`, `storage:write`, `http:outbound`, and `secrets:read` permissions. Revoking one blocks subsequent broker operations even for an already-running process.

## Host Protocol operations

The isolated process continues to POST JSON to `/v1/capabilities/{name}` with the existing per-instance bearer credential.

- `fs.read`: `{ "name": "reports", "path": "daily/summary.json" }` returns `{ "contentBase64": "..." }`.
- `fs.write`: `{ "name": "reports", "path": "daily/summary.json", "bodyBase64": "..." }` returns `{ "written": true }`.
- `http.fetch`: `{ "method": "GET", "url": "https://api.example.com/data" }` uses the hardened HTTPS broker. Hostnames and ports are matched **exactly** against `networkOutbound`; redirect following is disabled; public-IP/DNS rebinding checks and TLS hostname verification remain enforced by the existing HTTP fetcher.
- `http.fetch` with `{ "method": "GET", "url": "https://api.example.com/data", "secretName": "api_token" }` performs an **opaque** scoped operation: the backend retrieves only the extension's secret in the current scope and sends it as a `Bearer` Authorization header to the *signed, allowed* HTTPS origin. The token is never included in the extension response. Conflicting `Authorization` headers are rejected. **Raw `secret.get` is forbidden for isolated packages**, even if a legacy grant remains effective.

A `shared:<name>` grant does not grant direct mount access. Paths are slash-separated relative names only; `..`, `.`, absolute paths, empty components, symlinks (including parent-directory symlinks), and special files are rejected. Files are read with O_NOFOLLOW through pinned directory descriptors. Writes use a random temporary file + atomic `renameat`, so writes never follow or mutate hardlink/symlink targets outside the share. New files have `0600` permissions. Each read and write is limited to 256 KiB. Scratch remains a separately size-limited tmpfs in the Linux namespace.

**Operations not supported:** raw TCP/UDP sockets to the host network, direct filesystem mounts of shared resources, direct access to any secret as plaintext, arbitrary secret substitution into headers, callback/Java-host reverse RPC, and Windows/macOS OS sandboxing. They remain fail-closed until the relevant later stage. HTTP fetching remains HTTPS-only and cannot target private or loopback IPs even if an operator wrote such a hostname into the signed manifest.

## Acceptance tests

```sh
cd services/api
GOPROXY=off go test -race -tags neverlauncher_nopgx -count=1 ./internal/extensionbroker ./internal/linuxsandbox ./internal/extensionpolicy ./internal/extensionhost
# On CI with all external Go dependencies:
go test -race -count=1 ./internal/extensionbroker ./internal/linuxsandbox ./internal/extensionpolicy ./internal/extensionhost
# Only on a deliberately provisioned, unprivileged Linux runner with delegated cgroups v2:
NL_RUN_LIVE_LINUX_SANDBOX=1 go test -tags neverlauncher_nopgx -v ./internal/linuxsandbox -run TestLinuxIsolationLive0319
```

The included tests cover symlink/traversal/hardlink attacks, underspecified origins, unauthorized secret use, permission revocation, and missing resource mappings. The live cgroup/namespace test requires a real Linux deployment; passing unit tests cannot certify kernel isolation or full production-readiness.

# NeverLauncher 0.31.9 — Linux Native Extension Sandbox

## Executable boundary

Backend and CLI targets with an Ed25519-signed manifest `sandbox.mode: isolated` use the *same* Linux launch route. They are not passed to the legacy process-group launcher. The kernel creates new user, mount, PID, network, IPC and UTS namespaces. The child is born in its cgroup through `CLONE_INTO_CGROUP` (Go `UseCgroupFD`), not attached after it starts. This prevents initial-CPU/fork races.

The launcher establishes a private tmpfs root, recursively readonly mounts the verified package at `/package`, and mounts selected OS runtime libraries and executables read-only (`/usr`, `/bin`, `/lib*`, `/sbin`). `/etc`, `/home`, `/var`, and `/run` are *not mounted*; only the dynamic loader cache and system CA files are explicitly mounted from `/etc`. `/proc` is private to the PID namespace. `/tmp` and `/scratch` are separately quota-limited tmpfs mounts. `pivot_root` detaches the host filesystem. `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)` is mandatory: if recursive readonly restrictions cannot be applied, launch is rejected.

The bootstrap drops effective, permitted and inheritable capabilities, sets locked securebits, `PR_SET_NO_NEW_PRIVS`, and a BPF seccomp denylist for namespace changes, mount manipulation, ptrace/process_vm, kernel API attack surfaces and privileged calls. The extension is entered by `execve` on the same locked OS thread after verification of `/proc/self/status`. User namespaces are the equivalent isolation boundary; the host UID is mapped to namespace UID 0, **not** a distinct dedicated host UID. Deployment must run the Backend under a restricted non-root service identity; root services are refused.

`memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max` and `cgroup.kill` enforce resource boundaries. The cgroup is created under an already delegated cgroup-v2 subtree; absence of delegation or of any required controller results in a hard failure. The per-extension lifetime timer kills the whole cgroup on expiry, including grandchildren that create new process groups. No fallback to host process groups is allowed for isolated packages.

The network namespace has **only loopback**. An internal TCP listener bridges authenticated Host Protocol requests over a private, preopened Unix socketpair to the existing Backend HTTP handler. No host network path or Backend secret directory is visible. The configuration/token is passed in a sealed Linux memfd instead of an argv flag, on-disk file or environment variable. For now, shared filesystem, arbitrary outbound network and scoped secrets permissions are rejected; scoped brokers are scheduled for 0.31.10. Native callback URLs and Java callback RPC are also rejected until a secure reverse broker is available. Trusted/legacy packages continue in explicitly unisolated mode; signing alone never makes one isolated.

## Deployment prerequisites

- Linux x86-64, unprivileged service UID, user namespaces enabled, `clone3(CLONE_INTO_CGROUP)` available.
- cgroups v2 subtree delegated to NeverLauncher service (`memory`, `pids`, `cpu` controllers). Use an appropriate systemd service with `Delegate=yes` and ensure the service can create/write child cgroups. Do *not* grant root or ambient capabilities to overcome delegation failures.
- Kernel support for recursive `mount_setattr` (Linux 5.12+), `pivot_root`, seccomp filtering and tmpfs/proc in user namespaces.
- Use a dedicated, minimal `/usr` runtime root. Runtime directories are mounted readonly but their public readable contents remain visible. Do not store secrets under those runtime directories.
- Linux arm64 and non-Linux platforms refuse `isolated` until their native implementation is validated.

## Live acceptance and limits

Run on an explicitly provisioned machine:

`cd services/api && NL_RUN_LIVE_LINUX_SANDBOX=1 go test -v ./internal/linuxsandbox -run TestLinuxIsolationLive0319`

Must also validate with actual malicious extensions that network egress cannot occur, package write is impossible, Backend secrets cannot be read, descendants cannot escape cgroup limits after `setsid`, that the host API remains functional, and disabling kernel capabilities blocks launch. Run negative tests under a real service deployment. The conditional test is not equivalent to hardware/kernel certification. The sandbox is defense in depth, not a guarantee against kernel vulnerabilities.

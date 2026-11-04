# 0.31.11 — Windows AppContainer и объекты заданий

This release integrates the existing signed `sandbox.mode=isolated` policy into **native Windows process creation**, rather than labelling a normal process as isolated.

## порядок принудительного применения

1. The privileged host validates the signed policy, absolute executable path and configured grants, then creates a random per-launch AppContainer profile and SID.
2. `icacls` grants that SID read/execute on the immutable extension package. No backend settings, storage or secret directories are shared.
3. A random local named pipe uses a DACL tied to the new SID and low-integrity mandatory label. Only this pipe carries HTTP Host Protocol requests, protected by the existing instance bearer token. The AppContainer is given no network capabilities or loopback exemption.
4. A short-lived, self-executing helper calls `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, `EXTENDED_STARTUPINFO_PRESENT` and `CREATE_SUSPENDED`. It queries the **actual process token** for `TokenIsAppContainer` and `TokenAppContainerSid` and fails on mismatch.
5. Before the target can run, the helper attaches it to a Job Object with `KILL_ON_JOB_CLOSE`, active process count, process/job memory caps and CPU hard cap. No breakaway flags are enabled. A two-way control pipe registers the real PID before `ResumeThread`.
6. The helper owns the Job until exit or timeout. Terminating the helper closes the Job, killing all descendants. Sandbox setup failures stop launch: no fallback to trusted mode.
7. Both Backend and CLI use this path. UI/API status reports `windows-appcontainer` only after the child has been verified, job-assigned, resumed and acknowledged.

## поддерживаемые платформы

Native, signed `.exe` extension targets that communicate over the updated Go Backend or CLI SDK through `LAUNCHER_EXTENSION_HOST_PIPE`. Other extension clients must explicitly implement HTTP/1.1 over the SID-restricted named pipe, including bearer authentication. Unsandboxed fallback is forbidden.

Java callbacks and any application requiring direct outbound network or a loopback listener are not supported in Windows isolated mode. Scoped network and secret requests remain accessible through Host Protocol. The *shared filesystem broker* from 0.31.10 currently remains unavailable on Windows: secure handle-relative NT filesystem operations are required before this grant can be enabled. Configuration with shared roots fails closed. The AppContainer scratch directory is writable; the package is read-only.

AppContainer is not equivalent to LPAC and does not prove absence of ALL APPLICATION PACKAGES-readable objects or OS escape vulnerabilities. The trust indicator describes enforced OS sandbox boundaries, not absolute anti-cheat or kernel integrity.

## приёмка и развёртывание

Use Windows 10/11 or supported Windows Server with working AppContainer API and standard Job Object facilities. The service identity needs permission to create AppContainer profiles and adjust package ACLs. Do not run the API as an elevated interactive administrator unnecessarily. Keep extension payload packages immutable and restrict write access to deployment roles.

Run from a Windows machine:

```powershell
cd services/api
$env:NL_RUN_LIVE_WIN_SANDBOX='1'
go test -tags launcher_nopgx -count=1 -v ./internal/windowssandbox
```

The test creates a **real** AppContainer process, asserts it cannot read private backend files or change package contents, probes denied direct outbound access and attempts to exceed its Job active-process limit. Test failures must block deployment; availability checks and compilation alone do not certify the kernel isolation.

## 0.43.10 нативная приёмка Windows и контрольное чтение применённой политики

The sandbox helper reads the **live kernel Job configuration** (membership, process count, both memory caps, CPU hard cap and breakaway flags) after attaching the suspended AppContainer child and **before** resuming its main thread. If any value is missing or differs from the signed policy, it terminates the Job and refuses launch. The helper also verifies the actual AppContainer SID on the child token. This protects against assuming that successful Win32 setup calls imply effective restrictions.

Recursive package ACL grants cannot cross reparse points or directory junctions. `icacls` must report success for the entire package and runs from the OS system directory, never from a PATH-selected binary. The Windows shared-root filesystem broker is still unavailable: `shared:*` grants fail closed. Host-protocol broker requests for approved network/secrets remain separate from direct network access, which AppContainer is not granted. Both IPC pipe modes deny remote clients; the single-instance ready pipe also rejects pre-existing instances of its randomized name.

**Required live jobs:** `.github/workflows/windows-extension-sandbox-03111.yml` runs the sandbox boundary tests on native `windows/amd64` and a self-hosted native `windows/arm64` runner with label `launcher-appcontainer`. A missing runner or failed system policy must leave native acceptance unverified; a Windows x64 build or ARM64 cross-compile cannot replace the ARM64 Job kernel test. The tests include killing a running isolated process by closing the owning helper's Job handle and proving that it actually terminates.

These tests validate the native extension sandbox subsystem. Independent end-to-end gaming, anti-cheat, signed package hashes and the six-target release evidence gate still apply separately.

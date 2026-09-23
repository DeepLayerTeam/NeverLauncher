#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label} missing: {', '.join(missing)}")


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"invalid VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 13, 3):
    raise SystemExit(f"NeverGuard process policy gate requires >=0.13.3, got {version}")

cargo = read("runtime/neverruntime/Cargo.toml")
require(cargo, [
    '"Win32_System_JobObjects"',
    '"Win32_System_Diagnostics_ToolHelp"',
    '"Win32_System_Threading"',
], "NeverRuntime Windows policy dependencies")

policy = read("runtime/neverruntime/src/windows_policy.rs")
require(policy, [
    'neverguard/windows-runtime-process-policy/v1',
    'SetProcessMitigationPolicy',
    'GetProcessMitigationPolicy',
    'ProcessDynamicCodePolicy',
    'ProcessExtensionPointDisablePolicy',
    'ProcessStrictHandleCheckPolicy',
    'ProcessImageLoadPolicy',
    'ProcessChildProcessPolicy',
    'CreateJobObjectW',
    'SetInformationJobObject',
    'AssignProcessToJobObject',
    'IsProcessInJob',
    'QueryInformationJobObject',
    'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE',
    'JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION',
    'JOB_OBJECT_LIMIT_BREAKAWAY_OK',
    'JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK',
    'CREATE_SUSPENDED',
    'ResumeThread',
    'TH32CS_SNAPTHREAD',
    'prepare_runtime_command',
    'enforce_runtime_process',
    'runtime_process_is_suspended_assigned_and_resumed',
], "Windows runtime/process policy implementation")

neverguard = read("runtime/neverruntime/src/bin/neverguard.rs")
if neverguard.find("ensure_guard_process_policy()") > neverguard.find("tokio::runtime::Builder"):
    raise SystemExit("NeverGuard self policy must be enforced before Tokio runtime initialization")

guard = read("runtime/neverruntime/src/guard_ipc.rs")
require(guard, [
    'NEVERGUARD_PROTOCOL_VERSION: u32 = 3',
    'process_policy_version',
    'process_policy_enforced',
    'send_command(handle, "process-policy")',
    '"process-policy" =>',
    'validate_guard_process_policy',
    'NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION',
], "Authenticated process-policy IPC")

supervisor = read("runtime/neverruntime/src/supervisor.rs")
require(supervisor, [
    'prepare_runtime_command(&mut command)',
    'enforce_runtime_process(&mut child)',
    'windows_process_policy',
    'runtime_policy: Some(runtime_policy)',
    'Windows runtime/process policy enforcement failed',
], "Runtime supervisor fail-closed process policy")

runtime = read("runtime/neverruntime/src/lib.rs")
require(runtime, [
    'windows_policy::prepare_runtime_command(&mut command)',
    'windows_policy::enforce_runtime_process(&mut child)',
    'RuntimeProcessPolicyReport',
], "Direct NeverRuntime policy enforcement")

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(desktop, [
    'status.process_policy_enforced',
    'NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION',
    '.process_policy()',
    'launch заблокирован: NeverGuard Windows process policy verification failed',
    'neverguard_process_policy',
], "Desktop policy pre-launch gate")

integration = read("runtime/neverruntime/tests/neverguard_windows.rs")
require(integration, [
    'NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA',
    'NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION',
    '.process_policy()',
    'dynamic_code_prohibited',
    'child_process_creation_blocked',
], "Windows NeverGuard policy integration test")

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "neverguard-process-policy-0133.py" not in ci:
    raise SystemExit("NeverGuard 0.13.3 process policy gate is not wired into CI")
if "neverguard-process-policy-0133.py" not in preflight:
    raise SystemExit("NeverGuard 0.13.3 process policy gate is not wired into release preflight")
require(ci, [
    'cargo test --manifest-path runtime/neverruntime/Cargo.toml --lib windows_policy::tests',
    'cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_windows',
    'cargo clippy --manifest-path runtime/neverruntime/Cargo.toml --all-targets -- -D warnings',
], "Windows native policy CI")

security = read("SECURITY.md")
require(security, [
    "NeverGuard Windows: применение runtime/process policy — 0.13.3",
    "CREATE_SUSPENDED",
    "Job Object",
    "KILL_ON_JOB_CLOSE",
    "JIT",
], "NeverGuard 0.13.3 security boundary")

print(f"[NeverLauncher] NeverGuard Windows runtime/process policy 0.13.3 gate OK: {version}")

#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(
            f"[NeverLauncher] Поток и Процесс Целостность 0.18.6 контроль: {label} отсутствующий {missing}"
        )


def main() -> int:
    version = read("VERSION").strip()
    if tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 6):
        raise SystemExit(f"[NeverLauncher] Поток и Процесс Целостность 0.18.6 контроль: VERSION является {version}")

    thread_sensor = read("runtime/neverguard-sensor/src/thread_integrity.rs")
    sensor = read("runtime/neverguard-sensor/src/lib.rs")
    policy = read("runtime/neverruntime/src/windows_policy.rs")
    parent = read("runtime/neverruntime/src/windows_module_guard.rs")
    report = read("runtime/neverruntime/src/windows_thread_process_integrity.rs")
    exports = read("runtime/neverruntime/src/lib.rs")
    bootstrap = read("runtime/neverruntime/src/windows_sensor.rs")
    integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    probe = read("runtime/neverguard-thread-probe/src/lib.rs")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(
        thread_sensor,
        [
            "CreateToolhelp32Snapshot",
            "TH32CS_SNAPTHREAD",
            "NtQueryInformationThread",
            "THREAD_QUERY_SET_WIN32_START_ADDRESS",
            "VirtualQuery",
            "MEM_IMAGE",
            "suspicious runtime transition",
            "non-image executable memory",
            "thread-set v1",
            "origin-set v1",
            "reconcile_and_verify",
        ],
        "real thread enumeration/start-origin validation engine",
    )
    for forbidden in ("CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "NtWriteVirtualMemory"):
        if forbidden in thread_sensor:
            raise SystemExit(
                f"[NeverLauncher] Поток и Процесс Целостность 0.18.6 контроль: forbidden cross-процесс primitive {forbidden}"
            )

    require(
        sensor,
        [
            "mod thread_integrity;",
            "MODULE_EVENT_REASON_THREAD_PROCESS_READY",
            "MODULE_EVENT_REASON_THREAD_PROCESS_HEARTBEAT",
            "MODULE_EVENT_REASON_THREAD_PROCESS_TAMPER",
            "THREAD_INTEGRITY_CHECK_INTERVAL",
            "thread_integrity::initialize()",
            "thread_integrity::reconcile_and_verify()",
            "thread_integrity::shutdown()",
            "thread_process_event(",
        ],
        "Sensor startup/continuous thread lifecycle",
    )
    require(
        policy,
        [
            "pub struct RuntimeProcessTreeSnapshot",
            "verify_process_tree",
            "TH32CS_SNAPPROCESS",
            "Process32FirstW",
            "Process32NextW",
            "IsProcessInJob",
            "escaped runtime Job Object",
            "process-tree v1",
            "breakaway_allowed: false",
        ],
        "real Job Object process-tree verification",
    )
    require(
        bootstrap,
        [
            "runtime_policy: Option<crate::RuntimeProcessPolicyGuard>",
            "bind_runtime_policy",
            "requires runtime Job Object policy binding",
        ],
        "Sensor/runtime policy binding",
    )
    require(
        parent,
        [
            "thread_process_integrity: crate::WindowsThreadProcessIntegrityReport",
            "expected THREAD_PROCESS_READY as third event",
            "thread_process_report_from_event",
            "runtime_policy.verify_process_tree(pid)",
            "MODULE_EVENT_REASON_THREAD_PROCESS_HEARTBEAT",
            "MODULE_EVENT_REASON_THREAD_PROCESS_TAMPER",
            "fail_closed",
        ],
        "authenticated parent evidence/process-tree enforcement",
    )
    require(
        report,
        [
            "NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION: u32 = 1",
            "pub struct WindowsThreadProcessIntegrityReport",
            "baseline_thread_count",
            "current_thread_count",
            "new_thread_count",
            "retired_thread_count",
            "descendant_process_peak",
            "process_transition_count",
            "thread_set_sha256",
            "thread_origin_set_sha256",
            "process_tree_sha256",
        ],
        "runtime evidence report",
    )
    require(
        exports,
        [
            "pub mod windows_thread_process_integrity;",
            "WindowsThreadProcessIntegrityReport",
            "RuntimeProcessTreeSnapshot",
        ],
        "runtime exports",
    )
    require(
        integration,
        [
            "NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION",
            "neverguard_thread_process_integrity_tracks_job_bound_descendant_processes",
            "descendant_process_peak >= 1",
            "neverguard_thread_integrity_fail_closed_on_private_executable_thread_start",
            "private executable thread start must be fail-closed",
            "bind_runtime_policy(&runtime_policy)",
        ],
        "real Windows JVM process-tree/thread-tamper regressions",
    )
    require(
        probe,
        [
            "JNI_OnLoad",
            "VirtualAlloc",
            "CreateThread",
            "PAGE_EXECUTE_READWRITE",
            "create_private_executable_thread",
        ],
        "adversarial MEM_PRIVATE thread-start fixture",
    )
    require(
        ci,
        [
            "python scripts/smoke/offline/neverguard-thread-process-integrity-0186.py",
            "cargo build --manifest-path runtime/neverguard-thread-probe/Cargo.toml",
            "NEVERGUARD_THREAD_PROBE_DLL",
            "cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/neverguard-thread-probe/Cargo.toml --all-targets -- -D warnings",
        ],
        "Windows integration/adversarial/clippy CI",
    )
    if "neverguard-thread-process-integrity-0186.py" not in preflight:
        raise SystemExit("[NeverLauncher] Поток и Процесс Целостность 0.18.6 контроль: предварительная проверка wiring отсутствующий")

    for path, body in [
        ("runtime/neverguard-sensor/src/thread_integrity.rs", thread_sensor),
        ("runtime/neverguard-sensor/src/lib.rs", sensor),
        ("runtime/neverruntime/src/windows_policy.rs", policy),
        ("runtime/neverruntime/src/windows_module_guard.rs", parent),
    ]:
        for forbidden in ("todo!()", "unimplemented!()", "TODO: stub", "foundation placeholder"):
            if forbidden in body:
                raise SystemExit(
                    f"[NeverLauncher] Поток и Процесс Целостность 0.18.6 контроль: placeholder {forbidden!r} в {path}"
                )

    print("[NeverLauncher] Поток и Процесс Целостность 0.18.6 контроль: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

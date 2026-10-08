#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"[NeverLauncher] Модуль Защита 0.18.3 контроль: {label} отсутствующий {missing}")


def main() -> int:
    version = read("VERSION").strip()
    if tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 3):
        raise SystemExit(f"[NeverLauncher] Модуль Защита 0.18.3 контроль: VERSION является {version}")

    sensor = read("runtime/neverguard-sensor/src/lib.rs")
    parent = read("runtime/neverruntime/src/windows_module_guard.rs")
    bootstrap = read("runtime/neverruntime/src/windows_sensor.rs")
    supervisor = read("runtime/neverruntime/src/supervisor.rs")
    integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(
        sensor,
        [
            "LdrRegisterDllNotification",
            "LdrUnregisterDllNotification",
            "module_notification",
            "MODULE_RING_CAPACITY",
            "reserve_module_slot",
            "MODULE_DROPPED_EVENTS",
            "MODULE_EVENT_REASON_LOADED",
            "MODULE_EVENT_REASON_UNLOADED",
            "MODULE_EVENT_REASON_HEARTBEAT",
            "MODULE_EVENT_REASON_OVERFLOW",
            "MODULE_EVENT_REASON_SHUTDOWN",
            "MODULE_EVENT_MAGIC",
            "MODULE_EVENT_DOMAIN",
            "wait_for_module_guard_arm",
            "MODULE_WORKER_HANDLE",
            "handle.join()",
            "std::process::abort()",
        ],
        "native continuous DLL event producer",
    )
    require(
        parent,
        [
            "pub struct WindowsModuleGuardReport",
            "pub struct WindowsModuleGuardSession",
            "pub async fn arm_module_guard",
            "parse_event_packet",
            "expected_sequence",
            "ct_eq",
            "MODULE_STREAM_TIMEOUT",
            "module_snapshot(pid)",
            "reconcile_snapshot",
            "external snapshot drift",
            "validate_loaded_module",
            "verify_windows_authenticode_trust",
            "sha256_file",
            "advance_event_chain",
            "TerminateProcess",
            "fail_closed",
        ],
        "parent-side continuous enforcement/evidence",
    )
    require(
        bootstrap,
        [
            "NEVERGUARD_SENSOR_PROTOCOL_VERSION",
            "SENSOR_MAGIC",
            "SENSOR_DOMAIN",
            "policy_for_command",
            "arm_module_guard",
            "WindowsSensorSession",
            "pub fn report(&self) -> WindowsSensorReport",
        ],
        "Sensor bootstrap to Module Guard arm binding",
    )
    require(
        supervisor,
        [
            "sensor_session: Option<crate::WindowsSensorSession>",
            "process_status_snapshot",
            "session.report()",
        ],
        "live supervised Module Guard evidence",
    )
    require(
        integration,
        [
            "neverguard_module_guard_tracks_real_jvm_dll_load_and_heartbeat",
            "System.load(args[0])",
            "report.load_events >= 1",
            "report.heartbeat_count >= 1",
            "neverguard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots",
            "unsigned module outside trusted roots must be fail-closed",
            "report.violation_count >= 1",
        ],
        "real JVM DLL load/enforcement regression tests",
    )
    require(
        ci,
        [
            "python scripts/smoke/offline/neverguard-module-guard-0183.py",
            "cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/neverguard-sensor/Cargo.toml --all-targets -- -D warnings",
            "cargo clippy --manifest-path runtime/neverruntime/Cargo.toml --all-targets -- -D warnings",
        ],
        "Windows CI compile/integration/clippy enforcement",
    )
    if "neverguard-module-guard-0183.py" not in preflight:
        raise SystemExit("[NeverLauncher] Модуль Защита 0.18.3 контроль: предварительная проверка wiring отсутствующий")

    for path, body in [
        ("runtime/neverguard-sensor/src/lib.rs", sensor),
        ("runtime/neverruntime/src/windows_module_guard.rs", parent),
        ("runtime/neverruntime/src/windows_sensor.rs", bootstrap),
    ]:
        for forbidden in ("todo!()", "unimplemented!()", "TODO: stub", "foundation placeholder"):
            if forbidden in body:
                raise SystemExit(
                    f"[NeverLauncher] Модуль Защита 0.18.3 контроль: placeholder {forbidden!r} в {path}"
                )

    print("[NeverLauncher] Модуль Защита 0.18.3 контроль: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

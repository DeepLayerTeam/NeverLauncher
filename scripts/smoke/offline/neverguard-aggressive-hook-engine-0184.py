#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"[NeverLauncher] Агрессивный Хук Движок I 0.18.4 контроль: {label} отсутствующий {missing}")


def main() -> int:
    version = read("VERSION").strip()
    if tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 4):
        raise SystemExit(f"[NeverLauncher] Агрессивный Хук Движок I 0.18.4 контроль: VERSION является {version}")

    engine = read("runtime/neverguard-sensor/src/hook_engine.rs")
    sensor = read("runtime/neverguard-sensor/src/lib.rs")
    parent = read("runtime/neverruntime/src/windows_module_guard.rs")
    report = read("runtime/neverruntime/src/windows_hook_engine.rs")
    bootstrap = read("runtime/neverruntime/src/windows_sensor.rs")
    integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(
        engine,
        [
            "collect_hook_candidates",
            "IMAGE_DIRECTORY_ENTRY_IMPORT",
            "GetProcAddress",
            "VirtualProtect",
            "FlushInstructionCache",
            "hook_load_library_a",
            "hook_load_library_w",
            "hook_load_library_ex_a",
            "hook_load_library_ex_w",
            "hook_virtual_alloc",
            "hook_virtual_protect",
            "pre-existing IAT target drift",
            "verify_locked",
            "shutdown_restore",
            "read_volatile",
            "write_volatile",
            "hook_set_digest",
            "should_skip_module",
        ],
        "real bounded IAT interception/self-integrity backend",
    )
    for forbidden in ("SetWindowsHookEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory"):
        if forbidden in engine:
            raise SystemExit(
                f"[NeverLauncher] Агрессивный Хук Движок I 0.18.4 контроль: cross/global-process primitive forbidden: {forbidden}"
            )

    require(
        sensor,
        [
            "mod hook_engine;",
            "SENSOR_PROTOCOL_VERSION: u32 = 3",
            "NGSENS04",
            "NGARM004",
            "NGMOD004",
            "MODULE_EVENT_REASON_HOOK_READY",
            "MODULE_EVENT_REASON_HOOK_HEARTBEAT",
            "MODULE_EVENT_REASON_HOOK_TAMPER",
            "hook_engine::initialize()",
            "hook_engine::reconcile_and_verify()",
            "hook_engine::shutdown_restore()",
            "module_worker(channel, sequence",
        ],
        "Sensor startup/continuous hook lifecycle",
    )
    require(
        parent,
        [
            "hook_engine: crate::WindowsHookEngineReport",
            "expected HOOK_READY as first event",
            "hook_digest_from_event",
            "MODULE_EVENT_REASON_HOOK_HEARTBEAT",
            "MODULE_EVENT_REASON_HOOK_TAMPER",
            "hooked_module_count",
            "hooked_slot_count",
            "intercepted_call_count",
            "integrity_check_count",
            "Hook Engine integrity violation",
            "fail_closed",
        ],
        "parent-side authenticated readiness/evidence/fail-closed enforcement",
    )
    require(
        report,
        [
            "NEVERGUARD_HOOK_ENGINE_VERSION: u32 = 1",
            "pub struct WindowsHookEngineReport",
            "hooked_module_count",
            "hooked_slot_count",
            "intercepted_call_count",
            "integrity_check_count",
            "hook_set_sha256",
        ],
        "runtime hook evidence",
    )
    require(
        bootstrap,
        [
            "NEVERGUARD_SENSOR_PROTOCOL_VERSION: u32 = 3",
            "NGSENS04",
            "neverguard-sensor-startup-v3",
            "authenticate_sensor_or_kill",
        ],
        "protocol-v3 fail-closed bootstrap",
    )
    require(
        integration,
        [
            "NEVERGUARD_HOOK_ENGINE_VERSION",
            "report.module_guard.hook_engine.active",
            "report.module_guard.hook_engine.hooked_slot_count > 0",
            "report.hook_engine.integrity_check_count >= 2",
            "report.hook_engine.intercepted_call_count >= 1",
            "report.hook_engine.hook_set_sha256.len(), 64",
        ],
        "real JVM interception/self-check integration regression",
    )
    require(
        ci,
        [
            "python scripts/smoke/offline/neverguard-aggressive-hook-engine-0184.py",
            "cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/neverguard-sensor/Cargo.toml --all-targets -- -D warnings",
            "cargo clippy --manifest-path runtime/neverruntime/Cargo.toml --all-targets -- -D warnings",
        ],
        "Windows compilation/integration/clippy CI",
    )
    if "neverguard-aggressive-hook-engine-0184.py" not in preflight:
        raise SystemExit("[NeverLauncher] Агрессивный Хук Движок I 0.18.4 контроль: предварительная проверка wiring отсутствующий")

    for path, body in [
        ("runtime/neverguard-sensor/src/hook_engine.rs", engine),
        ("runtime/neverguard-sensor/src/lib.rs", sensor),
        ("runtime/neverruntime/src/windows_module_guard.rs", parent),
    ]:
        for forbidden in ("todo!()", "unimplemented!()", "TODO: stub", "foundation placeholder"):
            if forbidden in body:
                raise SystemExit(
                    f"[NeverLauncher] Агрессивный Хук Движок I 0.18.4 контроль: placeholder {forbidden!r} в {path}"
                )

    print("[NeverLauncher] Агрессивный Хук Движок I 0.18.4 контроль: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

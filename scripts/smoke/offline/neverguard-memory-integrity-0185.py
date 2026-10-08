#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"[NeverLauncher] Память Целостность 0.18.5 контроль: {label} отсутствующий {missing}")


def main() -> int:
    version = read("VERSION").strip()
    if tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 5):
        raise SystemExit(f"[NeverLauncher] Память Целостность 0.18.5 контроль: VERSION является {version}")

    memory = read("runtime/neverguard-sensor/src/memory_integrity.rs")
    hooks = read("runtime/neverguard-sensor/src/hook_engine.rs")
    sensor = read("runtime/neverguard-sensor/src/lib.rs")
    parent = read("runtime/neverruntime/src/windows_module_guard.rs")
    report = read("runtime/neverruntime/src/windows_memory_integrity.rs")
    exports = read("runtime/neverruntime/src/lib.rs")
    integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    probe = read("runtime/neverguard-memory-probe/src/lib.rs")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(
        memory,
        [
            "VirtualQuery",
            "MEM_IMAGE",
            "MEM_PRIVATE",
            "MEM_MAPPED",
            "PAGE_EXECUTE_READWRITE",
            "hash_image_region",
            "code-page drift",
            "executable private memory without observed VirtualAlloc/VirtualProtect provenance",
            "transition ring overflow",
            "record_virtual_alloc",
            "record_virtual_protect",
            "executable-map v1",
            "code-set v1",
            "GetModuleHandleExW",
            "Sha256::digest",
        ],
        "real executable-memory scan/code-page baseline/provenance engine",
    )
    for forbidden in ("WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "NtWriteVirtualMemory"):
        if forbidden in memory:
            raise SystemExit(f"[NeverLauncher] Память Целостность 0.18.5 контроль: cross-процесс primitive forbidden: {forbidden}")

    require(
        hooks,
        [
            "crate::memory_integrity::record_virtual_alloc",
            "crate::memory_integrity::record_virtual_protect",
        ],
        "real VirtualAlloc/VirtualProtect transition feed",
    )
    require(
        sensor,
        [
            "mod memory_integrity;",
            "MODULE_EVENT_REASON_MEMORY_READY",
            "MODULE_EVENT_REASON_MEMORY_HEARTBEAT",
            "MODULE_EVENT_REASON_MEMORY_TAMPER",
            "memory_integrity::initialize()",
            "memory_integrity::reconcile_and_verify()",
            "memory_integrity::shutdown()",
            "memory_event(MODULE_EVENT_REASON_MEMORY_READY",
        ],
        "Sensor startup/continuous Memory Integrity lifecycle",
    )
    require(
        parent,
        [
            "memory_integrity: crate::WindowsMemoryIntegrityReport",
            "expected MEMORY_READY as second event",
            "memory_report_from_event",
            "MODULE_EVENT_REASON_MEMORY_HEARTBEAT",
            "MODULE_EVENT_REASON_MEMORY_TAMPER",
            "Memory Integrity runtime tampering detected",
            "fail_closed",
        ],
        "parent authenticated readiness/evidence/fail-closed enforcement",
    )
    require(
        report,
        [
            "NEVERGUARD_MEMORY_INTEGRITY_VERSION: u32 = 1",
            "pub struct WindowsMemoryIntegrityReport",
            "executable_region_count",
            "image_code_region_count",
            "dynamic_executable_region_count",
            "rwx_region_count",
            "observed_transition_count",
            "code_set_sha256",
            "executable_map_sha256",
        ],
        "runtime Memory Integrity evidence",
    )
    require(exports, ["pub mod windows_memory_integrity;", "WindowsMemoryIntegrityReport"], "runtime exports")
    require(
        integration,
        [
            "NEVERGUARD_MEMORY_INTEGRITY_VERSION",
            "report.module_guard.memory_integrity.active",
            "report.memory_integrity.integrity_check_count >= 2",
            "neverguard_memory_integrity_fail_closed_on_executable_image_code_page_drift",
            "executable image code-page drift must be fail-closed",
        ],
        "real Windows JVM Memory Integrity regressions",
    )
    require(
        probe,
        ["JNI_OnLoad", "VirtualProtect", "write_volatile", "neverguard_memory_probe_target"],
        "adversarial in-process code-drift fixture",
    )
    require(
        ci,
        [
            "python scripts/smoke/offline/neverguard-memory-integrity-0185.py",
            "cargo build --manifest-path runtime/neverguard-memory-probe/Cargo.toml",
            "NEVERGUARD_MEMORY_PROBE_DLL",
            "cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/neverguard-memory-probe/Cargo.toml --all-targets -- -D warnings",
        ],
        "Windows compilation/adversarial integration/clippy CI",
    )
    if "neverguard-memory-integrity-0185.py" not in preflight:
        raise SystemExit("[NeverLauncher] Память Целостность 0.18.5 контроль: предварительная проверка wiring отсутствующий")

    for path, body in [
        ("runtime/neverguard-sensor/src/memory_integrity.rs", memory),
        ("runtime/neverguard-sensor/src/lib.rs", sensor),
        ("runtime/neverruntime/src/windows_module_guard.rs", parent),
    ]:
        for forbidden in ("todo!()", "unimplemented!()", "TODO: stub", "foundation placeholder"):
            if forbidden in body:
                raise SystemExit(f"[NeverLauncher] Память Целостность 0.18.5 контроль: placeholder {forbidden!r} в {path}")

    print("[NeverLauncher] Память Целостность 0.18.5 контроль: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

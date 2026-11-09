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
            f"[Launcher] Memory Integrity 0.18.5: проверка — {label}: отсутствует {missing}"
        )


def main() -> int:
    version = read("VERSION").strip()
    if tuple(
        int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]
    ) < (0, 18, 5):
        raise SystemExit(
            f"[Launcher] Проверка целостности памяти 0.18.5: версия {version}"
        )

    memory = read("runtime/guard-sensor/src/memory_integrity.rs")
    hooks = read("runtime/guard-sensor/src/hook_engine.rs")
    sensor = read("runtime/guard-sensor/src/lib.rs")
    parent = read("runtime/runtime/src/windows_module_guard.rs")
    report = read("runtime/runtime/src/windows_memory_integrity.rs")
    exports = read("runtime/runtime/src/lib.rs")
    integration = read("runtime/runtime/tests/guard_sensor_windows.rs")
    probe = read("runtime/guard-memory-probe/src/lib.rs")
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
        "сканирование исполняемой памяти, контроль страниц и происхождения",
    )
    for forbidden in (
        "WriteProcessMemory",
        "VirtualAllocEx",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
    ):
        if forbidden in memory:
            raise SystemExit(
                f"[Launcher] Проверка целостности памяти 0.18.5: запрещённая межпроцессная операция: {forbidden}"
            )

    require(
        hooks,
        [
            "crate::memory_integrity::record_virtual_alloc",
            "crate::memory_integrity::record_virtual_protect",
        ],
        "отслеживание переходов VirtualAlloc/VirtualProtect",
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
        "запуск датчика и постоянный контроль целостности памяти",
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
        "подтверждение родителя, свидетельств и запрета при ошибке",
    )
    require(
        report,
        [
            "GUARD_MEMORY_INTEGRITY_VERSION: u32 = 1",
            "pub struct WindowsMemoryIntegrityReport",
            "executable_region_count",
            "image_code_region_count",
            "dynamic_executable_region_count",
            "rwx_region_count",
            "observed_transition_count",
            "code_set_sha256",
            "executable_map_sha256",
        ],
        "свидетельства целостности памяти Runtime",
    )
    require(
        exports,
        ["pub mod windows_memory_integrity;", "WindowsMemoryIntegrityReport"],
        "экспорт Runtime",
    )
    require(
        integration,
        [
            "GUARD_MEMORY_INTEGRITY_VERSION",
            "report.module_guard.memory_integrity.active",
            "report.memory_integrity.integrity_check_count >= 2",
            "guard_memory_integrity_fail_closed_on_executable_image_code_page_drift",
            "executable image code-page drift must be fail-closed",
        ],
        "регрессионные тесты целостности памяти JVM Windows",
    )
    require(
        probe,
        ["JNI_OnLoad", "VirtualProtect", "write_volatile", "guard_memory_probe_target"],
        "тестовый сценарий изменения кода внутри процесса",
    )
    require(
        ci,
        [
            "python scripts/smoke/offline/guard-memory-integrity-0185.py",
            "cargo build --manifest-path runtime/guard-memory-probe/Cargo.toml",
            "GUARD_MEMORY_PROBE_DLL",
            "cargo test --manifest-path runtime/runtime/Cargo.toml --test guard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/guard-memory-probe/Cargo.toml --all-targets -- -D warnings",
        ],
        "CI сборки Windows, проверок атак и Clippy",
    )
    if "guard-memory-integrity-0185.py" not in preflight:
        raise SystemExit(
            "[Launcher] Memory Integrity 0.18.5: не настроен запуск в предварительных проверках"
        )

    for path, body in [
        ("runtime/guard-sensor/src/memory_integrity.rs", memory),
        ("runtime/guard-sensor/src/lib.rs", sensor),
        ("runtime/runtime/src/windows_module_guard.rs", parent),
    ]:
        for forbidden in (
            "todo!()",
            "unimplemented!()",
            "TODO: stub",
            "foundation placeholder",
        ):
            if forbidden in body:
                raise SystemExit(
                    f"[Launcher] Проверка целостности памяти 0.18.5: заглушка {forbidden!r} в {path}"
                )

    print("[Launcher] Контроль целостности памяти 0.18.5: проверка: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

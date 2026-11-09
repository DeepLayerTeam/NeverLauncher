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
            f"[Launcher] Aggressive Hook Engine I 0.18.4: проверка — {label}: отсутствует {missing}"
        )


def main() -> int:
    version = read("VERSION").strip()
    if tuple(
        int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]
    ) < (0, 18, 4):
        raise SystemExit(
            f"[Launcher] Проверка агрессивного движка перехватов I 0.18.4: версия {version}"
        )

    engine = read("runtime/guard-sensor/src/hook_engine.rs")
    sensor = read("runtime/guard-sensor/src/lib.rs")
    parent = read("runtime/runtime/src/windows_module_guard.rs")
    report = read("runtime/runtime/src/windows_hook_engine.rs")
    bootstrap = read("runtime/runtime/src/windows_sensor.rs")
    integration = read("runtime/runtime/tests/guard_sensor_windows.rs")
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
            "AtomicUsize::from_ptr",
            "Ordering::Acquire",
            "Ordering::Release",
            "hook_set_digest",
            "should_skip_module",
        ],
        "Реальный ограниченный перехват IAT и самопроверка целостности Backend",
    )
    # JVM может напрямую импортировать нативные API памяти ntdll. Наблюдать их нужно
    # через точно типизированные обёртки только текущего процесса; ошибочный
    # NTSTATUS никогда не даёт подтверждённого происхождения исполняемой страницы.
    require(
        engine,
        [
            'name: "NtAllocateVirtualMemory"',
            'name: "NtProtectVirtualMemory"',
            "fn hook_nt_allocate_virtual_memory(",
            "fn hook_nt_protect_virtual_memory(",
            'import_dll.eq_ignore_ascii_case("ntdll.dll")',
            "status >= 0 && is_current_process_handle(process)",
            "fn is_current_process_handle(process: *mut c_void) -> bool",
            "record_virtual_alloc(address, size, protect)",
            "record_virtual_protect(address, size, protect)",
        ],
        "Происхождение памяти текущего процесса NT с блокировкой по ошибке NTSTATUS",
    )
    for forbidden in (
        "SetWindowsHookEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
    ):
        if forbidden in engine:
            raise SystemExit(
                f"[Launcher] Проверка агрессивного движка перехватов I 0.18.4: запрещена межпроцессная или общепроцессная операция {forbidden}"
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
        "Жизненный цикл начальных и непрерывных перехватов датчика",
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
        "Проверка готовности, свидетельств и блокировки при ошибке в родительском процессе",
    )
    require(
        report,
        [
            "GUARD_HOOK_ENGINE_VERSION: u32 = 1",
            "pub struct WindowsHookEngineReport",
            "hooked_module_count",
            "hooked_slot_count",
            "intercepted_call_count",
            "integrity_check_count",
            "hook_set_sha256",
        ],
        "Свидетельства перехвата Runtime",
    )
    require(
        bootstrap,
        [
            "GUARD_SENSOR_PROTOCOL_VERSION: u32 = 3",
            "NGSENS04",
            "guard-sensor-startup-v3",
            "authenticate_sensor_or_kill",
        ],
        "Строгая инициализация протокола v3 с блокировкой при ошибке",
    )
    require(
        integration,
        [
            "GUARD_HOOK_ENGINE_VERSION",
            "report.module_guard.hook_engine.active",
            "report.module_guard.hook_engine.hooked_slot_count > 0",
            "report.hook_engine.integrity_check_count >= 2",
            "report.hook_engine.intercepted_call_count >= 1",
            "report.hook_engine.hook_set_sha256.len(), 64",
        ],
        "Интеграционные регрессионные проверки перехвата и самопроверки настоящей JVM",
    )
    require(
        ci,
        [
            "python scripts/smoke/offline/guard-aggressive-hook-engine-0184.py",
            "cargo test --manifest-path runtime/runtime/Cargo.toml --test guard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/guard-sensor/Cargo.toml --all-targets -- -D warnings",
            "cargo clippy --manifest-path runtime/runtime/Cargo.toml --all-targets -- -D warnings",
        ],
        "Компиляция, интеграция и Clippy для Windows в CI",
    )
    if "guard-aggressive-hook-engine-0184.py" not in preflight:
        raise SystemExit(
            "[Launcher] Aggressive Hook Engine I 0.18.4: не настроен запуск в предварительных проверках"
        )

    for path, body in [
        ("runtime/guard-sensor/src/hook_engine.rs", engine),
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
                    f"[Launcher] Проверка агрессивного движка перехватов I 0.18.4: заглушка {forbidden!r} в {path}"
                )

    print("[Launcher] Усиленный механизм контроля перехватов I 0.18.4: проверка: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

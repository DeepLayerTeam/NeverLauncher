#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствуют {', '.join(missing)}")


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"Некорректное значение VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 13, 3):
    raise SystemExit(f"Проверка политики процессов Guard: требуется версия не ниже 0.13.3, получена {version}")

cargo = read("runtime/runtime/Cargo.toml")
require(
    cargo,
    [
        '"Win32_System_JobObjects"',
        '"Win32_System_Diagnostics_ToolHelp"',
        '"Win32_System_Threading"',
    ],
    "Зависимости политики Runtime для Windows",
)

policy = read("runtime/runtime/src/windows_policy.rs")
require(
    policy,
    [
        "guard/windows-runtime-process-policy/v1",
        "SetProcessMitigationPolicy",
        "GetProcessMitigationPolicy",
        "ProcessDynamicCodePolicy",
        "ProcessExtensionPointDisablePolicy",
        "ProcessStrictHandleCheckPolicy",
        "ProcessImageLoadPolicy",
        "ProcessChildProcessPolicy",
        "CreateJobObjectW",
        "SetInformationJobObject",
        "AssignProcessToJobObject",
        "IsProcessInJob",
        "QueryInformationJobObject",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        "JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION",
        "JOB_OBJECT_LIMIT_BREAKAWAY_OK",
        "JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK",
        "CREATE_SUSPENDED",
        "ResumeThread",
        "TH32CS_SNAPTHREAD",
        "prepare_runtime_command",
        "enforce_runtime_process",
        "runtime_process_is_suspended_assigned_and_resumed",
    ],
    "Реализация политики Runtime и процессов Windows",
)

guard = read("runtime/runtime/src/bin/guard.rs")
if guard.find("ensure_guard_process_policy()") > guard.find("tokio::runtime::Builder"):
    raise SystemExit(
        "Собственная политика Guard должна применяться до инициализации Runtime Tokio"
    )

guard = read("runtime/runtime/src/guard_ipc.rs")
require(
    guard,
    [
        "GUARD_PROTOCOL_VERSION: u32 = 4",
        "process_policy_version",
        "process_policy_enforced",
        'send_command(handle, "process-policy")',
        '"process-policy" =>',
        "validate_guard_process_policy",
        "GUARD_WINDOWS_PROCESS_POLICY_VERSION",
    ],
    "Аутентифицированный IPC для политики процессов",
)

supervisor = read("runtime/runtime/src/supervisor.rs")
require(
    supervisor,
    [
        "prepare_runtime_command(&mut command)",
        "enforce_runtime_process(&mut child)",
        "windows_process_policy",
        "runtime_policy: Some(runtime_policy)",
        "не удалось применить политику Runtime и процессов Windows",
    ],
    "Строгая политика процессов наблюдателя Runtime",
)

runtime = read("runtime/runtime/src/lib.rs")
require(
    runtime,
    [
        "windows_policy::prepare_runtime_command(&mut command)",
        "windows_policy::enforce_runtime_process(&mut child)",
        "RuntimeProcessPolicyReport",
    ],
    "Прямое применение политики Runtime",
)

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        "status.process_policy_enforced",
        "GUARD_WINDOWS_PROCESS_POLICY_VERSION",
        ".process_policy()",
        "Запуск заблокирован: не удалось проверить политику процессов Guard для Windows",
        "guard_process_policy",
    ],
    "Проверка политики Desktop перед запуском",
)

integration = read("runtime/runtime/tests/guard_windows.rs")
require(
    integration,
    [
        "GUARD_WINDOWS_PROCESS_POLICY_SCHEMA",
        "GUARD_WINDOWS_PROCESS_POLICY_VERSION",
        ".process_policy()",
        "dynamic_code_prohibited",
        "child_process_creation_blocked",
    ],
    "Интеграционный тест политики Windows Guard",
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "guard-process-policy.py" not in ci:
    raise SystemExit("Guard 0.13.3: проверка политики процессов не подключена к CI")
if "guard-process-policy.py" not in preflight:
    raise SystemExit(
        "Проверка политики процессов Guard 0.13.3: не подключена к предварительной проверке релиза"
    )
require(
    ci,
    [
        "cargo test --manifest-path runtime/runtime/Cargo.toml --lib windows_policy::tests",
        "cargo test --manifest-path runtime/runtime/Cargo.toml --test guard_windows",
        "cargo clippy --manifest-path runtime/runtime/Cargo.toml --all-targets -- -D warnings",
    ],
    "Нативная проверка политики Windows в CI",
)

# Документация безопасности Markdown необязательна; выполнение правил проверено выше.
print(f"[Launcher] Проверка политики среды выполнения и процессов Guard для Windows 0.13.3: OK; версия={version}")

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
if version_tuple(version) < (0, 13, 2):
    raise SystemExit(f"Подтверждение целостности Guard: требуется версия не ниже 0.13.2, получено {version}")

cargo = read("runtime/runtime/Cargo.toml")
require(
    cargo,
    [
        "[target.'cfg(windows)'.dependencies]",
        'windows-sys = { version = "0.61.2"',
        '"Win32_Security_WinTrust"',
        '"Win32_System_Diagnostics_ToolHelp"',
        '"Win32_System_Threading"',
    ],
    "Зависимости Runtime для Windows",
)

integrity = read("runtime/runtime/src/integrity.rs")
require(
    integrity,
    [
        "GUARD_INTEGRITY_EVIDENCE_VERSION: u32 = 1",
        "guard/windows-integrity-evidence/v1",
        "GuardIntegrityEvidence",
        "ProcessIntegrityEvidence",
        "AuthenticodeEvidence",
        "ProcessMitigationEvidence",
        "ModuleSetEvidence",
        "QueryFullProcessImageNameW",
        "GetProcessTimes",
        "GetProcessMitigationPolicy",
        "WinVerifyTrust",
        "WINTRUST_ACTION_GENERIC_VERIFY_V2",
        "WTD_CACHE_ONLY_URL_RETRIEVAL",
        "CreateToolhelp32Snapshot",
        "Process32FirstW",
        "Module32FirstW",
        "TH32CS_SNAPMODULE32",
        "sha256_file",
        "let module_sha256 = sha256_file(&path)?;",
        "module_set_sha256",
        "observed_parent_pid",
        "PID родительского процесса не совпадает",
        "recompute_evidence_sha256",
        "validate_evidence_shape",
    ],
    "Реализация свидетельств целостности Windows v1",
)

guard = read("runtime/runtime/src/guard_ipc.rs")
require(
    guard,
    [
        'send_command(handle, "integrity-evidence")',
        '"integrity-evidence" =>',
        "collect_windows_integrity_evidence",
        "spawn_blocking",
        "integrity_session_proof",
        "Не удалось проверить контрольную сумму свидетельства целостности Guard",
        "Не удалось проверить доказательство сеанса контроля целостности Guard",
        "observed_windows_parent_pid",
    ],
    "Команда проверки целостности аутентифицированного IPC",
)

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        "GuardIntegrityEvidence",
        ".integrity_evidence()",
        "Запуск заблокирован: подтверждение целостности Guard v1 для Windows недоступно",
        "guard_integrity_evidence",
    ],
    "Подключение строгой проверки целостности в Desktop",
)

integration = read("runtime/runtime/tests/guard_windows.rs")
require(
    integration,
    [
        "GUARD_INTEGRITY_EVIDENCE_SCHEMA",
        "GUARD_INTEGRITY_EVIDENCE_VERSION",
        ".integrity_evidence()",
        "evidence.guard.image_sha256.len()",
        "evidence.launcher.image_sha256.len()",
        "evidence.session_proof.len()",
        "module_count > 0",
    ],
    "Интеграционный тест целостности Windows",
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "guard-integrity-evidence.py" not in ci:
    raise SystemExit("Guard 0.13.2: проверка целостности не подключена к CI")
if "guard-integrity-evidence.py" not in preflight:
    raise SystemExit("Guard 0.13.2: проверка целостности не подключена к предварительной проверке выпуска")

# Документация безопасности Markdown необязательна; выполнение правил проверено выше.
print(f"[Launcher] Проверка свидетельств целостности Guard для Windows v1: OK; версия={version}")

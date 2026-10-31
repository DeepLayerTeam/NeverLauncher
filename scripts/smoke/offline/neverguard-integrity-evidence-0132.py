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
if version_tuple(version) < (0, 13, 2):
    raise SystemExit(f"Guard integrity evidence gate requires >=0.13.2, got {version}")

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
    "Runtime Windows dependencies",
)

integrity = read("runtime/runtime/src/integrity.rs")
require(
    integrity,
    [
        "NEVERGUARD_INTEGRITY_EVIDENCE_VERSION: u32 = 1",
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
        "actual parent PID mismatch",
        "recompute_evidence_sha256",
        "validate_evidence_shape",
    ],
    "Windows Integrity Evidence v1 implementation",
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
        "evidence digest verification failed",
        "session proof verification failed",
        "observed_windows_parent_pid",
    ],
    "Authenticated IPC integrity command",
)

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        "GuardIntegrityEvidence",
        ".integrity_evidence()",
        "launch заблокирован: Guard Windows Integrity Evidence v1 недоступен",
        "guard_integrity_evidence",
    ],
    "Desktop fail-closed integrity wiring",
)

integration = read("runtime/runtime/tests/guard_windows.rs")
require(
    integration,
    [
        "NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA",
        "NEVERGUARD_INTEGRITY_EVIDENCE_VERSION",
        ".integrity_evidence()",
        "evidence.guard.image_sha256.len()",
        "evidence.launcher.image_sha256.len()",
        "evidence.session_proof.len()",
        "module_count > 0",
    ],
    "Windows integrity integration test",
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "guard-integrity-evidence-0132.py" not in ci:
    raise SystemExit("Guard 0.13.2 integrity gate is not wired into CI")
if "guard-integrity-evidence-0132.py" not in preflight:
    raise SystemExit("Guard 0.13.2 integrity gate is not wired into release preflight")

# Документация безопасности Markdown необязательна; выполнение правил проверено выше.
print(f"[Launcher] Guard Windows Integrity Evidence v1 gate OK: {version}")

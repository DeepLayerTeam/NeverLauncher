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
if version_tuple(version) < (0, 13, 6):
    raise SystemExit(f"Windows production hardening gate requires >=0.13.6, got {version}")

policy = read("runtime/neverruntime/src/windows_policy.rs")
require(policy, [
    "NEVERGUARD_WINDOWS_HARDENING_VERSION: u32 = 1",
    "HeapSetInformation",
    "HeapEnableTerminationOnCorruption",
    "SetDllDirectoryW",
    "SetDefaultDllDirectories",
    "LOAD_LIBRARY_SEARCH_APPLICATION_DIR",
    "LOAD_LIBRARY_SEARCH_SYSTEM32",
    "prepare_guard_command",
    "CREATE_SUSPENDED",
    "bind_guard_to_launcher_job",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "AssignProcessToJobObject",
    "IsProcessInJob",
    "ensure_windows_production_hardening",
], "Windows process/lifetime hardening")

guard = read("runtime/neverruntime/src/guard_ipc.rs")
require(guard, [
    "NEVERGUARD_PROTOCOL_VERSION: u32 = 4",
    "create_secure_pipe_server",
    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
    "current_windows_user_sid_string",
    "D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})",
    "ConvertSidToStringSidW",
    "create_with_security_attributes_raw",
    "reject_remote_clients(true)",
    "hardening_version",
    "hardening_enforced",
    "secure_pipe_acl",
    "lifetime_job_enforced",
    "package_manifest_verified",
    "verify_windows_package_manifest",
    "symlink_metadata",
    "Windows package artifact SHA-256 mismatch",
    "production Windows package manifest must require Authenticode",
    "verify_windows_authenticode_trust",
    "NeverLauncher NeverGuard IPC ready v4",
], "NeverGuard hardened IPC/package boundary")

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(desktop, [
    "ensure_windows_production_hardening()",
    "NEVERGUARD_WINDOWS_HARDENING_VERSION",
    "status.secure_pipe_acl",
    "status.lifetime_job_enforced",
    "status.package_manifest_verified",
    "Windows production hardening verification failed",
], "Desktop fail-closed production hardening")

binary = read("runtime/neverruntime/src/bin/neverguard.rs")
require(binary, [
    "ensure_windows_production_hardening",
    "ensure_guard_process_policy",
], "NeverGuard pre-runtime hardening")

release = read("scripts/release/build-windows-desktop.ps1")
require(release, [
    "CodeSigningCertificateThumbprint",
    "RequireCodeSigning",
    "AllowUnsignedDevelopmentPackage",
    "$SigningRequired = $RequireCodeSigning -or (-not $AllowUnsignedDevelopmentPackage)",
    "Set-AuthenticodeSignature",
    "Get-AuthenticodeSignature",
    "neverGuardProtocolVersion = 4",
    "windows-named-pipe+current-user-system-acl+hmac-sha256-v4",
    "authenticodeRequired = $AuthenticodeRequired",
    "requireAuthenticode = $AuthenticodeRequired",
    "packageVerification = \"sha256-before-neverguard-spawn\"",
], "Windows signed release pipeline")

integration = read("runtime/neverruntime/tests/neverguard_windows.rs")
require(integration, [
    "NEVERGUARD_WINDOWS_HARDENING_VERSION",
    "status.hardening_enforced",
    "status.secure_pipe_acl",
    "status.lifetime_job_enforced",
], "Windows native hardening integration")

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "windows-production-hardening-0136.py" not in ci:
    raise SystemExit("0.13.6 hardening gate is not wired into CI")
if "windows-production-hardening-0136.py" not in preflight:
    raise SystemExit("0.13.6 hardening gate is not wired into release preflight")
require(ci, [
    "cargo test --manifest-path runtime/neverruntime/Cargo.toml --lib windows_policy::tests",
    "cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_windows",
    "cargo clippy --manifest-path runtime/neverruntime/Cargo.toml --all-targets -- -D warnings",
    "build-windows-desktop.ps1 -AllowUnsignedDevelopmentPackage",
], "Windows native CI")

security = read("SECURITY.md")
require(security, [
    "Windows production hardening — 0.13.6",
    "current-user/System ACL",
    "KILL_ON_JOB_CLOSE",
    "Authenticode",
], "0.13.6 security documentation")

print(f"[NeverLauncher] Windows production hardening 0.13.6 gate OK: {version}")

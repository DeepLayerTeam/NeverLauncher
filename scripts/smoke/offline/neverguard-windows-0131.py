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
if version_tuple(version) < (0, 13, 1):
    raise SystemExit(f"NeverGuard Windows gate requires >=0.13.1, got {version}")

cargo = read("runtime/neverruntime/Cargo.toml")
require(cargo, ['name = "neverguard"', 'path = "src/bin/neverguard.rs"', '"net"', 'rand = "0.8"', 'hmac = "0.12"', 'subtle = "2"', 'zeroize = "1"'], "NeverRuntime Cargo")

guard = read("runtime/neverruntime/src/guard_ipc.rs")
require(guard, [
    r'\\.\pipe\NeverLauncher.Guard.',
    "first_pipe_instance(true)",
    "reject_remote_clients(true)",
    "max_instances(1)",
    "BOOTSTRAP_SECRET_LEN",
    "stdin",
    'b"server"',
    'b"client"',
    'b"session-key"',
    "hmac_sha256",
    "constant_time_eq",
    "request_mac",
    "response_mac",
    "expected_sequence",
    "replay/out-of-order request rejected",
    "IPC_COMMAND_TIMEOUT_SECS",
    "IPC_STARTUP_AUTH_WINDOW_SECS",
    "server.disconnect()",
    "zeroize",
], "NeverGuard authenticated IPC")

binary = read("runtime/neverruntime/src/bin/neverguard.rs")
require(binary, ["--pipe", "--parent-pid", "run_windows_guard_server"], "NeverGuard process entrypoint")

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(desktop, [
    "NeverGuardSupervisor",
    ".manage(NeverGuardSupervisor::new())",
    "neverguard.ensure_started().await?",
    "neverguard.ping().await?",
    "launch заблокирован: NeverGuard Windows boundary",
    "neverguard_status",
], "Desktop fail-closed NeverGuard launch")

integration = read("runtime/neverruntime/tests/neverguard_windows.rs")
require(integration, [
    'env!("CARGO_BIN_EXE_neverguard")',
    "ensure_started().await",
    "authenticated",
    "supervisor.ping().await",
    "supervisor.shutdown().await",
], "NeverGuard Windows integration test")

package = read("scripts/release/build-windows-desktop.ps1")
require(package, [
    "neverguard.exe",
    "neverlauncher-desktop-$Version-windows-amd64.exe",
    "cargo build --release",
    "WINDOWS_PACKAGE_MANIFEST.json",
    "Compress-Archive",
], "Windows release packaging")

ci = read(".github/workflows/ci.yml")
require(ci, [
    "neverguard-windows:",
    "neverguard_windows",
    "build-windows-desktop.ps1",
], "NeverGuard Windows CI")

security = read("SECURITY.md")
require(security, ["NeverGuard Windows 0.13.1", "bootstrap secret", "Named Pipe", "sequence"], "NeverGuard security documentation")

print(f"[NeverLauncher] NeverGuard Windows authenticated IPC gate OK: {version}")

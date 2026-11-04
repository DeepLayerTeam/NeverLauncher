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
    raise SystemExit(f"Guard Windows gate requires >=0.13.1, got {version}")

cargo = read("runtime/runtime/Cargo.toml")
require(
    cargo,
    [
        'name = "guard"',
        'path = "src/bin/guard.rs"',
        '"net"',
        'rand = "0.8"',
        'hmac = "0.12"',
        'subtle = "2"',
        'zeroize = "1"',
    ],
    "Runtime Cargo",
)

guard = read("runtime/runtime/src/guard_ipc.rs")
require(
    guard,
    [
        r"\\.\pipe\Launcher.Guard.",
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
    ],
    "Guard authenticated IPC",
)

binary = read("runtime/runtime/src/bin/guard.rs")
require(
    binary,
    ["--pipe", "--parent-pid", "run_windows_guard_server"],
    "Guard process entrypoint",
)

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        "GuardSupervisor",
        ".manage(GuardSupervisor::new())",
        "guard.ensure_started().await?",
        "guard.ping().await?",
        "launch заблокирован: Guard Windows boundary",
        "guard_status",
    ],
    "Desktop fail-closed Guard launch",
)

integration = read("runtime/runtime/tests/guard_windows.rs")
require(
    integration,
    [
        'env!("CARGO_BIN_EXE_guard")',
        "ensure_started().await",
        "authenticated",
        "supervisor.ping().await",
        "supervisor.shutdown().await",
    ],
    "Guard Windows integration test",
)

package = read("scripts/release/build-windows-desktop.ps1")
require(
    package,
    [
        "guard.exe",
        "launcher-desktop-$Version-windows-amd64.exe",
        "cargo build --release",
        "WINDOWS_PACKAGE_MANIFEST.json",
        "Compress-Archive",
    ],
    "Windows release packaging",
)

ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        "guard-windows:",
        "guard_windows",
        "build-windows-desktop.ps1",
    ],
    "Guard Windows CI",
)

# Документация безопасности Markdown необязательна; выполнение правил проверено выше.
print(f"[Launcher] Guard Windows authenticated IPC gate OK: {version}")

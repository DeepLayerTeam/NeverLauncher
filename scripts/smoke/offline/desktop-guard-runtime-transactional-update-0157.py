#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 7):
    raise SystemExit(f"Desktop/Guard/Runtime transactional update gate requires VERSION>=0.15.7, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


core_go = read("cli/cmd/neverlauncher/component_update.go")
require(core_go, [
    "applyComponentPackage0157", "applyAdjacentComponentUpdate0157", "applyComponentTree0157",
    "recoverComponentTreesLocked0157", "rollbackComponentTreeLocked0157",
    "authenticode-rfc3161", "sha256-delivery", "developer-id-notarized",
    "--expected-sha256", "component update package SHA-256 mismatch",
    '[]string{"desktop", "guard", "runtime"}', "macosTreeRollback",
], "component transactional updater")

main_go = read("cli/cmd/neverlauncher/main.go")
require(main_go, ['case "components":', 'case "component-self-test":', '"--wait-pid"', '"--restart"'], "update CLI")

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(desktop, [
    "install_launcher_update", "neverguard.shutdown().await", "update", "components",
    "--expected-sha256", "--current-desktop", "--wait-pid", "--restart", "exit_handle.exit(0)",
], "Desktop updater handoff")

windows = read("scripts/release/build-windows-desktop.ps1")
require(windows, [
    'neverruntime.exe', 'neverlauncher-cli.exe', 'COMPONENT_UPDATE_MANIFEST.json',
    'component = "desktop"', 'component = "guard"', 'component = "runtime"',
    'authenticode-rfc3161',
], "Windows package")

linux = read("scripts/release/linux-package.py")
require(linux, ["COMPONENT_UPDATE_MANIFEST.json", '"desktop"', '"guard"', '"runtime"', '"sha256-delivery"'], "Linux package")

mac = read("scripts/release/macos-package.py") + read("scripts/release/build-macos-production.sh")
require(mac, [
    "COMPONENT_UPDATE_MANIFEST.json", "macos-app-bundle", "developer-id-notarized",
    "adhoc-development", "neverlauncher-desktop", "neverguard", "neverruntime",
], "macOS package")

rust = read("runtime/neverruntime/src/guard_ipc.rs") + read("runtime/neverruntime/src/linux_guard.rs") + read("runtime/neverruntime/src/macos_guard.rs")
require(rust, ["canonical_arch", "canonical_identity", "package_path", "MacOSPackageArtifact"], "Guard canonical package verification")

tests = read("cli/cmd/neverlauncher/component_update_test.go")
require(tests, [
    "TestComponentUpdateAdjacentCommit0157", "TestComponentTreePostVerifyFailureRollsBack0157",
    "TestComponentUpdateRequiresPinnedProductionArchive0157",
], "component update regression tests")

ci = read(".github/workflows/ci.yml")
if "desktop-guard-runtime-transactional-update-0157.py" not in ci or ci.count("update component-self-test") < 4:
    raise SystemExit("0.15.7 component updater native CI coverage is incomplete")
preflight = read("scripts/release/preflight.sh")
if "desktop-guard-runtime-transactional-update-0157.py" not in preflight:
    raise SystemExit("0.15.7 component updater preflight gate missing")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestComponent|TestWindows|TestLinux|TestMacOS", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Desktop/Guard/Runtime transactional update gate: OK")

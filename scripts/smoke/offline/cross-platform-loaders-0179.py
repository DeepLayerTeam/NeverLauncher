#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split(".")[:3])
if core < (0, 17, 9):
    raise SystemExit(f"Cross-platform Loaders requires VERSION>=0.17.9, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")

anchors = {"fabric": ("26.3", 25), "quilt": ("26.3", 25), "forge": ("26.3", 25), "neoforge": ("26.2", 25)}
platforms = {("linux", "x86_64"), ("linux", "aarch64"), ("windows", "x86_64"), ("windows", "aarch64"), ("macos", "x86_64"), ("macos", "aarch64")}
targets = json.loads((ROOT / "compatibility/targets.json").read_text(encoding="utf-8"))["targets"]
for loader, (minecraft, java) in anchors.items():
    rows = [row for row in targets if row.get("required") and row.get("loader") == loader and row.get("minecraft") == minecraft]
    actual = {(row.get("os"), row.get("arch")) for row in rows}
    if len(rows) != 6 or actual != platforms:
        raise SystemExit(f"{loader} {minecraft}: expected six cross-platform targets, got {len(rows)} {sorted(actual)}")
    for row in rows:
        if row.get("javaMajor") != java or row.get("scope") != "client" or row.get("loaderVersion") != "latest-stable":
            raise SystemExit(f"{row.get('id')}: invalid 0.17.9 cross-platform target contract")

helper = read("e2e/scripts/lib/certification-platform.sh")
require(helper, ["linux|windows|macos", "x86_64|aarch64", "certification_exe_suffix", "certification_run_client", 'if [[ "$os_name" == "linux" ]]', "xvfb-run"], "platform-native certification helper")
for loader in anchors:
    script = read(f"e2e/scripts/run-{loader}-certification-case.sh")
    require(script, ["certification-platform.sh", "certification_platform_validate", "certification_exe_suffix", "certification_run_client", "verify-loader-platform.py", "loader-platform.json"], f"{loader} platform certification")
    if 'TARGET_OS" != "linux"' in script or 'TARGET_ARCH" != "x86_64"' in script:
        raise SystemExit(f"{loader}: obsolete Linux/x86_64-only certification guard remains")

verifier = read("scripts/compatibility/verify-loader-platform.py")
require(verifier, ["materializerTargets", "nativeDirectory", "nativeFileCount", "nativeTreeSha256", "natives/{internal_os}/{arch}", '"osx" if os_name == "macos"'], "loader native verifier")
runtime = read("runtime/neverruntime/src/lib.rs")
require(runtime, ["natives_directory: String", "natives_dir.to_string_lossy().to_string()"], "NeverRuntime selected-native evidence")

matrix = read("scripts/compatibility/matrix.py")
require(matrix, ["CROSS_PLATFORM_LOADERS_0179", "cross_platform_loaders_0179_required", "Cross-platform Loaders 0.17.9", "loaderPlatformMaterialized", "loaderNativesResolved", "loaderPlatformLaunch", "loader-platform.json"], "matrix 0.17.9 enforcement")
compat = read("e2e/scripts/run-compatibility-case.sh")
require(compat, ["cross_platform_loader_anchors", "loaderPlatformMaterialized", "loaderNativesResolved", "loaderPlatformLaunch", "loader-platform.json", "nativesDirectory"], "compatibility result cross-platform evidence")
release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, ["CrossPlatformLoaderTargets", "compatibilityCrossPlatformLoaders0179Required", "compatibilityCrossPlatformLoaderTarget", "loaderPlatformMaterialized", "loaderNativesResolved", "loaderPlatformLaunch", "cross-platform-loaders-0.17.9-windows-linux-macos-x64-arm64-native-client"], "release certification 0.17.9")

workflow = read(".github/workflows/compatibility.yml")
require(workflow, ["architecture: ${{ matrix.arch == 'x86_64' && 'x64' || 'aarch64' }}", "e2e/runtime/loader-platform.json"], "cross-platform workflow")
require(matrix, ["ubuntu-24.04-arm", "windows-11-arm", "macos-15-intel", "macos-15"], "matrix hosted-runner mapping")

tests = read("scripts/compatibility/test_matrix.py") + read("scripts/compatibility/test_verify_loader_platform.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go")
require(tests, ["test_validate_0179_requires_all_loader_platforms", "test_aggregate_0179_requires_native_platform_check", "test_rejects_foreign_arch_native", "TestCompatibilityCertificationCrossPlatformLoaders0179", "TestCompatibilityCertificationCrossPlatformLoaders0179RejectsTamperedCoverage"], "0.17.9 regression tests")

print("Cross-platform Loaders 0.17.9 gate: OK (Fabric/Quilt/Forge/NeoForge on Windows/Linux/macOS x64/ARM64 with exact native-tree runtime evidence)")

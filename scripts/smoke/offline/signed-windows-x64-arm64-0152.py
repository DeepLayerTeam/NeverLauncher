#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 2):
    raise SystemExit(f"Signed Windows x64+ARM64 gate requires VERSION>=0.15.2, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


builder = read("scripts/release/build-windows-desktop.ps1")
require(
    builder,
    [
        'Architecture = "x64"',
        'Architecture = "arm64"',
        'RustTarget = "x86_64-pc-windows-msvc"',
        'RustTarget = "aarch64-pc-windows-msvc"',
        'Get-SignToolPath',
        '"/fd", "SHA256"',
        '"/tr", $TimestampServer',
        '"/td", "SHA256"',
        '"verify", "/pa", "/all", "/v"',
        'Import-PfxCertificate',
        'Assert-PEArchitecture',
        'WINDOWS_SIGNING_EVIDENCE.json',
        'GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json',
        'schemaVersion = "1.0"',
        'platform = "windows-amd64"',
        'windows-amd64-guard-ci-package',
    ],
    "Windows builder",
)

verifier = read("cli/cmd/neverlauncher/windows_signing.go")
require(
    verifier,
    [
        'const windowsSigningEvidenceFile0152 = "WINDOWS_SIGNING_EVIDENCE.json"',
        'const windowsDeliveryAllowlistFile0152 = "GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json"',
        'windowsSigningRequired0152',
        'inspectWindowsPEBytes0152',
        'case 0x8664:',
        'case 0xaa64:',
        'production publish requires Authenticode+RFC3161 Windows signing',
        'verifyWindowsPackage0152',
        'verifyWindowsDeliveryAllowlist0152',
        'verifyWindowsAuthenticodeNative0152',
        'signtool.exe',
        'Get-AuthenticodeSignature',
    ],
    "Windows signing verifier",
)

release = read("cli/cmd/neverlauncher/release_commands.go")
require(
    release,
    [
        'verifyWindowsSigningEvidence0152(args[1], manifestVersion, true)',
        'windows-x64-arm64-authenticode-evidence',
        'neverlauncher-cli-windows-arm64.exe',
        'WINDOWS_PACKAGE_MANIFEST_ARM64.json',
    ],
    "release integration",
)

build_release = read("scripts/release/build-release.sh")
require(
    build_release,
    [
        'NEVERLAUNCHER_WINDOWS_SIGNED_ARTIFACTS_DIR',
        'WINDOWS_DUAL_ARCH_REQUIRED',
        'GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json',
        'WINDOWS_SIGNING_EVIDENCE.json',
    ],
    "release staging",
)

workflow = read(".github/workflows/windows-production-delivery.yml")
require(
    workflow,
    [
        'WINDOWS_CODESIGN_PFX_BASE64',
        'WINDOWS_CODESIGN_PFX_PASSWORD',
        '-RequireCodeSigning',
        'delivery verify-windows',
        '--production',
    ],
    "production signing workflow",
)

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestWindows", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Signed Windows x64 + ARM64 gate: OK")

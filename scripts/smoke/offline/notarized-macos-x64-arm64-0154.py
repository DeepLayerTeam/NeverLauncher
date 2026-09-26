#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 4):
    raise SystemExit(f"Notarized macOS x64+ARM64 gate requires VERSION>=0.15.4, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


builder = read("scripts/release/build-macos-production.sh")
require(
    builder,
    [
        'RUST_TARGET="x86_64-apple-darwin"',
        'RUST_TARGET="aarch64-apple-darwin"',
        'GOOS=darwin GOARCH="${GOARCH}" CGO_ENABLED=0',
        'codesign --force --sign "${SIGN_IDENTITY}" --options runtime',
        'xcrun notarytool submit',
        '--wait --output-format json',
        'xcrun stapler staple',
        'xcrun stapler validate',
        '/usr/sbin/spctl --assess --type execute',
        'neverlauncher-desktop-${VERSION}-macos-${arch}.zip',
        'macos-package.py',
        'developer-id-notarized',
        'adhoc-development',
        'codesign --verify --strict --verbose=2 "${MACOS_DIR}/${binary}"',
    ],
    "macOS production builder",
)
if 'APP_SIGN_ARGS+=(--deep)' in builder or 'codesign --deep --force' in builder:
    raise SystemExit("macOS production builder must not use --deep while signing nested code")
if builder.count('codesign --verify --strict --verbose=2 "${MACOS_DIR}/${binary}"') < 2:
    raise SystemExit("macOS production builder must verify nested binaries both before and after outer bundle signing")

packager = read("scripts/release/macos-package.py")
require(
    packager,
    [
        '"x64": {"cpu": 0x01000007',
        '"arm64": {"cpu": 0x0100000C',
        'LC_CODE_SIGNATURE',
        'MACOS_PACKAGE_MANIFEST_',
        'MACOS_NOTARIZATION_EVIDENCE.json',
        'GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json',
        'notarytool result is not Accepted',
    ],
    "macOS package helper",
)

verifier = read("cli/cmd/neverlauncher/macos_delivery.go")
require(
    verifier,
    [
        'const macOSNotarizationEvidenceFile0154 = "MACOS_NOTARIZATION_EVIDENCE.json"',
        'const macOSDeliveryAllowlistFile0154 = "GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json"',
        'macOSProductionRequired0154',
        'inspectMacOSMachOBytes0154',
        'case 0x01000007:',
        'case 0x0100000c:',
        'LC_CODE_SIGNATURE',
        'production publish requires Developer ID + Apple notarization',
        'verifyMacOSNativePackage0154',
        'stapler", "validate"',
        'spctl, "--assess"',
        'verifyMacOSNotarizationEvidence0154',
    ],
    "macOS delivery verifier",
)

release = read("cli/cmd/neverlauncher/release_commands.go")
require(
    release,
    [
        'verifyMacOSNotarizationEvidence0154(args[1], manifestVersion, true)',
        'macos-x64-arm64-developer-id-notarization',
        'macOSProductionArtifacts0154(ver)',
        'MACOS_PACKAGE_MANIFEST_X64.json',
        'MACOS_PACKAGE_MANIFEST_ARM64.json',
    ],
    "release integration",
)

staging = read("scripts/release/build-release.sh")
require(
    staging,
    [
        'NEVERLAUNCHER_MACOS_PRODUCTION_ARTIFACTS_DIR',
        'MACOS_DUAL_ARCH_REQUIRED',
        'neverlauncher-desktop-${VERSION}-macos-${arch}.zip',
        'MACOS_NOTARIZATION_EVIDENCE.json',
    ],
    "release staging",
)

ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        'macos-production:',
        'build-macos-production.sh --allow-ad-hoc',
        'neverlauncher-macos-production-${{ github.sha }}',
        'NEVERLAUNCHER_MACOS_PRODUCTION_ARTIFACTS_DIR',
    ],
    "CI macOS delivery boundary",
)

workflow = read(".github/workflows/macos-production-delivery.yml")
require(
    workflow,
    [
        'MACOS_DEVELOPER_ID_P12_BASE64',
        'MACOS_DEVELOPER_ID_APPLICATION',
        'APPLE_NOTARY_KEY_ID',
        'APPLE_NOTARY_ISSUER_ID',
        'notarytool store-credentials',
        'build-macos-production.sh',
        'delivery verify-macos',
        '--production',
    ],
    "production notarization workflow",
)

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestMacOS", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} notarized macOS x64 + ARM64 gate: OK")

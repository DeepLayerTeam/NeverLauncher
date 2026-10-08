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
        'HELPERS_DIR="${APP_ROOT}/Contents/Helpers"',
        'codesign --verify --strict --verbose=2 "${MACOS_DIR}/neverlauncher-desktop"',
        'codesign --verify --strict --verbose=2 "${HELPERS_DIR}/${binary}"',
    ],
    "macOS production builder",
)
require(builder, [
    'cp "${ROOT_DIR}/runtime/neverruntime/target/${RUST_TARGET}/release/neverguard" "${HELPERS_DIR}/neverguard"',
    'cp "${GO_CLI}" "${HELPERS_DIR}/neverlauncher-cli"',
    'codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier ru.skif4er.neverlauncher "${APP_ROOT}"',
    'codesign --verify --deep --strict --verbose=2 "${APP_ROOT}"',
], "inside-out macOS signing")
if 'APP_SIGN_ARGS+=(--deep)' in builder or 'codesign --deep --force' in builder:
    raise SystemExit("macOS builder must never use --deep for signing; nested code is signed explicitly inside-out")
if 'codesign --verify --strict --verbose=2 "${file}"' not in builder or 'codesign --verify --strict --verbose=2 "${HELPERS_DIR}/${binary}"' not in builder:
    raise SystemExit("macOS builder must verify helper binaries both before and after outer bundle signing")
if 'file="${MACOS_DIR}/${binary}"' in builder or 'codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier ru.skif4er.neverlauncher "${MACOS_DIR}/neverlauncher-desktop"' in builder:
    raise SystemExit("macOS builder must not sign the bundle main executable as a standalone nested step")
helper_sign = builder.find('for binary in neverguard neverruntime neverlauncher-cli; do')
manifest_build = builder.find('macos-package.py" manifest')
app_sign = builder.find('codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier ru.skif4er.neverlauncher "${APP_ROOT}"')
if min(helper_sign, manifest_build, app_sign) < 0 or not (helper_sign < manifest_build < app_sign):
    raise SystemExit("macOS signing order must be helpers -> Resources manifest -> APP_ROOT")

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
        'Contents/Helpers/neverguard',
        'Contents/Helpers/neverruntime',
        'Contents/Helpers/neverlauncher-cli',
        'require_signature: bool = True',
        'require_signature=(component != "desktop-launcher")',
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
    ],
    "CI macOS delivery boundary",
)

workflow = read(".github/workflows/macos-production-delivery.yml")
require(
    workflow,
    [
        'workflow_call:',
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

production_release = read(".github/workflows/production-release-candidate.yml")
require(
    production_release,
    [
        'macos-production-notarized:',
        'uses: ./.github/workflows/macos-production-delivery.yml',
        'secrets: inherit',
        'neverlauncher-macos-notarized-${{ github.sha }}',
        'path: macos-production-artifacts',
        'NEVERLAUNCHER_MACOS_PRODUCTION_ARTIFACTS_DIR: ${{ github.workspace }}/macos-production-artifacts',
        'needs: [base-ci, windows-production-signed, macos-production-notarized]',
    ],
    "production release macOS notarization wiring",
)
if 'macos-production-notarized:' in ci or 'neverlauncher-macos-notarized-${{ github.sha }}' in ci:
    raise SystemExit("ordinary main CI must not require Apple production notarization credentials")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestMacOS", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} notarized macOS x64 + ARM64 gate: OK")

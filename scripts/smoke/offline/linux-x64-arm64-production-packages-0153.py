#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 3):
    raise SystemExit(f"Linux x64+ARM64 production package gate requires VERSION>=0.15.3, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


builder = read("scripts/release/build-linux-production.sh")
require(
    builder,
    [
        'x86_64|amd64) ARCH="x64"',
        'aarch64|arm64) ARCH="arm64"',
        'GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED=0',
        'neverlauncher-cli-linux-${ARCH}',
        'neverlauncher-api-linux-${ARCH}',
        'neverlauncher-desktop-linux-${ARCH}',
        'neverguard-linux-${ARCH}',
        'neverruntime-linux-${ARCH}',
        'linux-package.py',
        '--expected-arch',
    ],
    "native Linux production builder",
)

packager = read("scripts/release/linux-package.py")
require(
    packager,
    [
        '"x64": (62, "EM_X86_64")',
        '"arm64": (183, "EM_AARCH64")',
        'production package requires ELF64 little-endian',
        'neverlauncher/LINUX_PACKAGE_MANIFEST.json',
        'gzip.GzipFile',
        'mtime=0',
        'mode": "0755"',
    ],
    "deterministic Linux packager",
)

verifier = read("cli/cmd/neverlauncher/linux_delivery.go")
require(
    verifier,
    [
        'const linuxProductionEvidenceFile0153 = "LINUX_PRODUCTION_EVIDENCE.json"',
        'const linuxDeliveryAllowlistFile0153 = "GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json"',
        'linuxProductionRequired0153',
        'inspectLinuxELFBytes0153',
        'case 62:',
        'case 183:',
        'verifyLinuxPackageArchive0153',
        'verifyLinuxProductionEvidence0153',
        'writeLinuxProductionEvidence0153',
        'sha256+signed-release-bundle',
    ],
    "Linux delivery verifier",
)

release = read("cli/cmd/neverlauncher/release_commands.go")
require(
    release,
    [
        'verifyLinuxProductionEvidence0153(args[1], manifestVersion, true)',
        'linux-x64-arm64-production-packages',
        'linuxProductionArtifacts0153(ver)',
        'LINUX_PACKAGE_MANIFEST_X64.json',
        'LINUX_PACKAGE_MANIFEST_ARM64.json',
    ],
    "release integration",
)

staging = read("scripts/release/build-release.sh")
require(
    staging,
    [
        'NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR',
        'LINUX_DUAL_ARCH_REQUIRED',
        'neverlauncher-linux-${arch}-${VERSION}.tar.gz',
        'LINUX_PACKAGE_MANIFEST_$(tr',
        'neverlauncher-cli-linux-x64',
    ],
    "release staging",
)

ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        'linux-production:',
        'runner: ubuntu-24.04',
        'runner: ubuntu-24.04-arm',
        'build-linux-production.sh',
        'NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR',
        'neverlauncher-linux-production-${{ matrix.arch }}-${{ github.sha }}',
    ],
    "native Linux CI matrix",
)

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestLinuxProduction", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Linux x64 + ARM64 production packages gate: OK")

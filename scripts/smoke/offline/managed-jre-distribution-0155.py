#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 5):
    raise SystemExit(f"Managed JRE Distribution gate requires VERSION>=0.15.5, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


builder = read("scripts/release/managed-jre-distribution.py")
require(
    builder,
    [
        'API = "https://api.adoptium.net/v3"',
        '"image_type": "jre"',
        '"jvm_impl": "hotspot"',
        '"vendor": "eclipse"',
        'download_exact',
        'sourceSha256',
        'MANAGED_JRE_MANIFEST.json',
        'MANAGED_JRE_EVIDENCE.json',
        '("windows", "x64"',
        '("windows", "arm64"',
        '("linux", "x64"',
        '("linux", "arm64"',
        '("macos", "x64"',
        '("macos", "arm64"',
    ],
    "Managed JRE builder",
)

verifier = read("cli/cmd/neverlauncher/managed_jre_delivery.go")
require(
    verifier,
    [
        'const managedJREManifestFile0155 = "MANAGED_JRE_MANIFEST.json"',
        'const managedJREEvidenceFile0155 = "MANAGED_JRE_EVIDENCE.json"',
        'managedJREDistributionRequired0155',
        'inspectWindowsPEBytes0152',
        'inspectLinuxELFBytes0153',
        'inspectMacOSMachOBytes0154',
        'exact-vendor-archive-sha256',
        'DELIVERY_MANIFEST.json',
        'Managed JRE artifact %s is not bound',
    ],
    "Managed JRE verifier",
)

runtime = read("runtime/neverruntime/src/managed_java.rs")
require(
    runtime,
    [
        'ensure_managed_java_from_distribution',
        'NEVERLAUNCHER_MANAGED_JRE_MANIFEST',
        'NEVERLAUNCHER_MANAGED_JRE_MANIFEST_SHA256',
        'remote Managed JRE manifest требует',
        'Managed JRE target must preserve exact vendor archive SHA-256',
        'ensure_local_archive',
        'Managed JRE javaEntry mismatch',
    ],
    "NeverRuntime Managed JRE consumer",
)

release = read("cli/cmd/neverlauncher/release_commands.go")
require(
    release,
    [
        'verifyManagedJREDistribution0155(args[1], manifestVersion, true)',
        'managed-jre-temurin21-six-target-distribution',
        'managedJREArtifacts0155(ver)',
        'Managed JRE Distribution',
    ],
    "release integration",
)

staging = read("scripts/release/build-release.sh")
require(
    staging,
    [
        'NEVERLAUNCHER_MANAGED_JRE_ARTIFACTS_DIR',
        'MANAGED_JRE_REQUIRED',
        'MANAGED_JRE_MANIFEST.json',
        'MANAGED_JRE_EVIDENCE.json',
        'neverlauncher-jre-temurin21-',
    ],
    "release staging",
)

workflow = read(".github/workflows/managed-jre-production-delivery.yml")
require(
    workflow,
    [
        'Managed JRE Production Delivery',
        'managed-jre-distribution.py',
        'delivery verify-jre',
        'neverlauncher-managed-jre-',
    ],
    "Managed JRE production workflow",
)

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestManagedJRE", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Managed JRE Distribution gate: OK")

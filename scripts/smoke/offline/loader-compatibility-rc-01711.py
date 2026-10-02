#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split(".")[:3])
if core < (0, 17, 11):
    raise SystemExit(f"Loader Compatibility RC requires VERSION>=0.17.11, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")

cert = read("cli/cmd/neverlauncher/compatibility_release_certificate.go")
require(cert, [
    "LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json",
    "neverlauncher-loader-compatibility-release-certificate",
    "CompatibilityCertificationSHA256", "EvidenceRootSHA256", "CertificateID",
    "RequiredTargetCount", "PassedTargetCount", "LoaderFamilies", "Platforms",
    "immutableLoaderPins", "loaderNativeE2E", "crossPlatformLoaders", "loaderHardeningRecovery",
    "buildLoaderCompatibilityReleaseCertificate01711", "verifyLoaderCompatibilityReleaseCertificate01711",
    "loader-compatibility-rc-0.17.11-full-release-certificate-all-292-targets-evidence-root-signed-bundle",
], "full loader release certificate")

compat = read("cli/cmd/neverlauncher/compatibility_release.go")
require(compat, [
    "compatibilityReleaseCertificate01711Required", "writeLoaderCompatibilityReleaseCertificate01711",
    "verifyLoaderCompatibilityReleaseCertificate01711",
], "compatibility certification RC integration")

release = read("cli/cmd/neverlauncher/release_commands.go")
require(release, [
    "loaderCompatibilityReleaseCertificateFile01711", "loader-compatibility-rc-full-release-certificate",
    "loaderCompatibilityReleaseCertified", "loaderCompatibilityReleaseCertificateSha256",
], "signed release bundle RC integration")

production_workflow = read(".github/workflows/production-release-candidate.yml")
require(production_workflow, [
    "LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json", "requiredTargetCount == 292",
    "loaderCompatibilityReleaseCertified == true", "loaderCompatibilityReleaseCertificateSha256",
], "production release candidate RC assertion")

tests = read("cli/cmd/neverlauncher/compatibility_release_certificate_test.go")
require(tests, [
    "TestLoaderCompatibilityReleaseCertificate01711Complete",
    "TestLoaderCompatibilityReleaseCertificate01711RejectsTamperedRoot",
    "TestLoaderCompatibilityReleaseCertificate01711RejectsMissingCertificate",
    "TestLoaderCompatibilityReleaseCertificate01711EvidenceRootChanges",
], "0.17.11 RC regression tests")

targets = json.loads(read("compatibility/targets.json"))["targets"]
required = [row for row in targets if row.get("required")]
if len(required) != 292:
    raise SystemExit(f"Loader Compatibility RC 0.17.11 requires 292 required targets, got {len(required)}")
family_counts = Counter(row.get("loader") for row in required)
expected_families = {"vanilla": 109, "fabric": 53, "quilt": 53, "forge": 50, "neoforge": 27}
if dict(family_counts) != expected_families:
    raise SystemExit(f"Loader Compatibility RC family coverage mismatch: {dict(family_counts)} != {expected_families}")
platforms = {(row.get("os"), row.get("arch")) for row in required}
expected_platforms = {
    ("linux", "x86_64"), ("linux", "aarch64"),
    ("windows", "x86_64"), ("windows", "aarch64"),
    ("macos", "x86_64"), ("macos", "aarch64"),
}
if platforms != expected_platforms:
    raise SystemExit(f"Loader Compatibility RC platform coverage mismatch: {sorted(platforms)}")
if {row.get("javaMajor") for row in required} != {8, 16, 17, 21, 25}:
    raise SystemExit("Loader Compatibility RC must cover Java 8/16/17/21/25")

print("Loader Compatibility RC 0.17.11 gate: OK (292/292 targets, full evidence root, family/platform/Java coverage, signed release certificate)")

#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split(".")[:3])
if core < (0, 18, 0):
    raise SystemExit(f"Loader Compatibility GA requires VERSION>=0.18.0, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")

runtime = read("cli/cmd/neverlauncher/loader_ga.go")
require(runtime, [
    "loaderGASupport0180", "enforceLoaderGASupport0180", "validateLoaderGASupportPolicy0180",
    "loaderGASupportSHA2560180", "fabricCompatibilityII0171", "quiltCompatibilityII0172",
    "forgeModern0173", "forgeLegacy1122_0174", "forgeLegacy1710_0175", "neoForgeCompatibilityII0176",
    "outside the certified GA support surface", "requires Java",
], "runtime GA support policy")

meta = read("cli/cmd/neverlauncher/loader_runtime.go")
forge = read("cli/cmd/neverlauncher/forge_runtime.go")
for name, text in [("Fabric/Quilt materializer", meta), ("Forge/NeoForge materializer", forge)]:
    require(text, ["EnforceGASupport", "enforceLoaderGASupport0180", "compatibilityLoaderGA0180Required(version)"], name)

cert = read("cli/cmd/neverlauncher/compatibility_release_certificate.go")
require(cert, [
    'status = "ga-certified"', 'releaseStage = "ga"', "RuntimeSupportSHA256", "RuntimeSupportEntries",
    "LegacyForgeVersions", "gaRuntimeSupportEnforced", "legacyForgeGA",
    "loader-compatibility-ga-0.18.0-runtime-enforced-fabric-quilt-forge-neoforge-legacy-all-292-targets-signed-bundle",
], "GA release certificate")

release = read("cli/cmd/neverlauncher/release_commands.go")
require(release, [
    "loaderCompatibilityGA", "loaderCompatibilityGASupportSha256", "Loader Compatibility GA 0.18.0",
    "loaderGASupportSHA2560180", "ga-certified",
], "GA release publish enforcement")

workflow = read(".github/workflows/production-release-candidate.yml")
require(workflow, [
    'status == "ga-certified"', "loaderCompatibilityGA == true", "loaderCompatibilityGASupportSha256",
], "production GA workflow assertion")

tests = read("cli/cmd/neverlauncher/loader_ga_test.go") + read("cli/cmd/neverlauncher/compatibility_release_certificate_test.go")
require(tests, [
    "TestLoaderGASupport0180ExactCertifiedSurface", "TestLoaderGASupport0180RejectsJavaDrift",
    "TestLoaderGA0180ProductionParsersEnableRuntimeGuard", "TestLoaderGA0180ProductionParsersRejectUnsupportedConcreteVersionBeforeInstall", "TestLoaderCompatibilityGA0180CertificateBindsRuntimeSupport",
    "TestLoaderCompatibilityGA0180RejectsCertifiedRuntimeSurfaceDrift", "TestLoaderCompatibilityGA0180RejectsTamperedRuntimeSupportHash",
], "GA regression tests")

targets = json.loads(read("compatibility/targets.json"))["targets"]
required = [row for row in targets if row.get("required")]
if len(required) != 292:
    raise SystemExit(f"Loader Compatibility GA requires 292 required targets, got {len(required)}")
family_counts = Counter(row.get("loader") for row in required)
expected_families = {"vanilla": 109, "fabric": 53, "quilt": 53, "forge": 50, "neoforge": 27}
if dict(family_counts) != expected_families:
    raise SystemExit(f"Loader Compatibility GA family coverage mismatch: {dict(family_counts)}")

unique_versions = {
    loader: sorted({row["minecraft"] for row in required if row.get("loader") == loader})
    for loader in ("fabric", "quilt", "forge", "neoforge")
}
expected_unique = {"fabric": 48, "quilt": 48, "forge": 45, "neoforge": 22}
for loader, want in expected_unique.items():
    if len(unique_versions[loader]) != want:
        raise SystemExit(f"Loader Compatibility GA {loader} unique versions={len(unique_versions[loader])}, want={want}")
if "1.7.10" not in unique_versions["forge"] or "1.12.2" not in unique_versions["forge"]:
    raise SystemExit("Loader Compatibility GA must include Forge legacy 1.7.10 and 1.12.2")

print("Loader Compatibility GA 0.18.0 gate: OK (runtime-enforced 163 loader/version lines, 292/292 release targets, Fabric/Quilt/Forge/NeoForge + legacy)")

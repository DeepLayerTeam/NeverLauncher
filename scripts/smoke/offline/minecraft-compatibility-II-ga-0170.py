#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(p) for p in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 0):
    raise SystemExit(f"Minecraft Compatibility II GA requires VERSION>=0.17.0, got {version}")

def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")

targets = json.loads(read("compatibility/targets.json"))
vanilla = [row for row in targets["targets"] if row.get("required") and row.get("loader") == "vanilla"]
if len(vanilla) < 107 or len({row["minecraft"] for row in vanilla}) < 102:
    raise SystemExit("GA 0.17.0v2 Vanilla base is narrower than 107 targets / 102 unique releases")
if {8,16,17,21,25} - {row["javaMajor"] for row in vanilla}:
    raise SystemExit("GA JRE base does not cover Java 8/16/17/21/25")

legacy_0170v1 = {
    "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.3.1",
    "1.4.2", "1.4.4", "1.4.5", "1.4.6", "1.5", "1.5.1", "1.6.1", "1.6.2",
    "1.7.2", "1.7.3", "1.7.4", "1.7.5", "1.7.6", "1.7.7", "1.7.8", "1.7.9",
    "1.8", "1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7", "1.8.8",
    "1.9", "1.9.1", "1.9.2", "1.9.3", "1.10", "1.10.1", "1.11", "1.11.1", "1.12", "1.12.1",
    "1.13", "1.13.1", "1.14", "1.14.1", "1.14.2", "1.14.3", "1.15", "1.15.1",
    "1.16", "1.16.1", "1.16.2", "1.16.3", "1.16.4",
}
legacy_rows = {
    row["minecraft"]: row for row in vanilla
    if row["minecraft"] in legacy_0170v1 and row["os"] == "linux" and row["arch"] == "x86_64"
}
missing_legacy = sorted(legacy_0170v1 - set(legacy_rows))
if missing_legacy:
    raise SystemExit(f"GA 0.17.0v1 complete Legacy Vanilla grid missing: {missing_legacy}")
for minecraft, row in legacy_rows.items():
    if row["javaMajor"] != 8 or row["scope"] != "client":
        raise SystemExit(f"GA 0.17.0v1 Legacy Vanilla {minecraft} must be Java 8 scope=client")

java16_17_0170v2 = {
    "1.17": 16,
    "1.18": 17, "1.18.1": 17,
    "1.19": 17, "1.19.1": 17, "1.19.2": 17, "1.19.3": 17,
    "1.20": 17, "1.20.3": 17,
}
modern_rows = {
    row["minecraft"]: row for row in vanilla
    if row["minecraft"] in java16_17_0170v2 and row["os"] == "linux" and row["arch"] == "x86_64"
}
missing_modern = sorted(set(java16_17_0170v2) - set(modern_rows))
if missing_modern:
    raise SystemExit(f"GA 0.17.0v2 complete Java 16/17 Vanilla grid missing: {missing_modern}")
for minecraft, major in java16_17_0170v2.items():
    row = modern_rows[minecraft]
    if row["javaMajor"] != major or row["scope"] != "client":
        raise SystemExit(f"GA 0.17.0v2 Vanilla {minecraft} must be Java {major} scope=client")

require(read("scripts/compatibility/certify-jre.py"), [
    "executableSha256", "java.runtime.version", "java.vendor", "java.vm.name", "java.home",
    "detectedOS", "detectedArch", "certified",
], "JRE attestation")
require(read("e2e/scripts/run-compatibility-case.sh"), [
    "certify-jre.py", '"jreCertified"', '"jreVendor"', '"jreRuntimeVersion"', '"jreExecutableSha256"',
], "compatibility target JRE binding")
require(read("scripts/compatibility/matrix.py"), [
    "LEGACY_VANILLA_0170V1", "JAVA16_17_VANILLA_0170V2", "COMPATIBILITY_II_GA_MIN_UNIQUE_VANILLA", "jreCertified", "build_ga_jre_base", '"jreBase"',
], "GA matrix aggregation")
require(read("cli/cmd/neverlauncher/compatibility_release.go"), [
    "compatibilityLegacyVanilla0170v1Required", "compatibilityJava16_17Vanilla0170v2Required", "compatibilityIIGa0170Required", "JREExecutableSHA256", "JREBuilds",
    "legacy-vanilla-0.17.0v1-complete-53-release-grid-java8",
    "java16-17-vanilla-0.17.0v2-complete-9-release-grid-exact",
    "minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base",
], "GA release certification")
require(read("cli/cmd/neverlauncher/vanilla_runtime.go"), [
    "legacyVanilla0170v1Releases", "java16_17Vanilla0170v2Releases", "expectedJavaMajorForVanilla0170v2", "validateVanillaLaunchMetadata",
], "GA 0.17.0v2 Vanilla materializer")
require(read("runtime/neverruntime/src/compatibility.rs"), [
    "Legacy Vanilla requires Java 8", "expected_java_major_for_vanilla_0170v2", "0.17.0v2 requires exact Java",
    "metadata does not contain executable arguments.game or minecraftArguments",
], "GA 0.17.0v2 NeverRuntime execution")
require(read(".github/workflows/compatibility.yml"), ["java-runtime.json", "run-compatibility-case.sh"], "GA CI evidence")
require(read("scripts/smoke/offline/compatibility-matrix.sh"), ["test_certify_jre.py"], "GA preflight regression")

print(f"Minecraft Compatibility II GA 0.17.0 gate: OK / 0.17.0v2 Java 16/17 grid ({len(vanilla)} Vanilla targets, {len({row['minecraft'] for row in vanilla})} releases, Java 8/16/17/21/25)")

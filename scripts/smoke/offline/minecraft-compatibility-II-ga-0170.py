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
if len(vanilla) < 45 or len({row["minecraft"] for row in vanilla}) < 40:
    raise SystemExit("GA Vanilla base is narrower than 45 targets / 40 unique releases")
if {8,16,17,21,25} - {row["javaMajor"] for row in vanilla}:
    raise SystemExit("GA JRE base does not cover Java 8/16/17/21/25")

require(read("scripts/compatibility/certify-jre.py"), [
    "executableSha256", "java.runtime.version", "java.vendor", "java.vm.name", "java.home",
    "detectedOS", "detectedArch", "certified",
], "JRE attestation")
require(read("e2e/scripts/run-compatibility-case.sh"), [
    "certify-jre.py", '"jreCertified"', '"jreVendor"', '"jreRuntimeVersion"', '"jreExecutableSha256"',
], "compatibility target JRE binding")
require(read("scripts/compatibility/matrix.py"), [
    "COMPATIBILITY_II_GA_MIN_UNIQUE_VANILLA", "jreCertified", "build_ga_jre_base", '"jreBase"',
], "GA matrix aggregation")
require(read("cli/cmd/neverlauncher/compatibility_release.go"), [
    "compatibilityIIGa0170Required", "JREExecutableSHA256", "JREBuilds",
    "minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base",
], "GA release certification")
require(read(".github/workflows/compatibility.yml"), ["java-runtime.json", "run-compatibility-case.sh"], "GA CI evidence")
require(read("scripts/smoke/offline/compatibility-matrix.sh"), ["test_certify_jre.py"], "GA preflight regression")

print(f"Minecraft Compatibility II GA 0.17.0 gate: OK ({len(vanilla)} Vanilla targets, {len({row['minecraft'] for row in vanilla})} releases, Java 8/16/17/21/25)")

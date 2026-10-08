#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 5):
    raise SystemExit(f"Forge Legacy 1.7.10 requires VERSION>=0.17.5, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")

matrix_globals = runpy.run_path(str(ROOT / "scripts/compatibility/matrix.py"))
if dict(matrix_globals["FORGE_LEGACY_1710_0175"]) != {"1.7.10": 8}:
    raise SystemExit("Forge Legacy 1.7.10 canonical grid mismatch")

rows = [row for row in json.loads(read("compatibility/targets.json"))["targets"] if row.get("required") and row.get("loader") == "forge" and row.get("minecraft") == "1.7.10"]
if len(rows) != 1:
    raise SystemExit(f"Forge Legacy 0.17.5 requires exactly one Forge 1.7.10 target, got {len(rows)}")
row = rows[0]
if row.get("javaMajor") != 8 or row.get("scope") != "client" or row.get("os") != "linux" or row.get("arch") != "x86_64" or row.get("loaderVersion") != "latest-stable":
    raise SystemExit("Forge Legacy 1.7.10 must be latest-stable Java 8 client linux/x86_64")

runtime = read("cli/cmd/neverlauncher/forge_runtime.go")
require(runtime, [
    'case "1.7.10"', "cpw.mods.fml.common.launcher.FMLTweaker", "legacy-v1-universal",
    "normalizeForgeLegacyRuntimeProfile", "canonicalLegacyForgeURL", "files.minecraftforge.net",
    "legacyTweaker", "legacyBaseVersion", "legacyProfileNormalized", "extractInstallerEntry",
    "verifyForgeLegacyUniversal", "net.minecraft.launchwrapper.Launch",
], "Forge 1.7.10 legacy materializer")

commands = read("cli/cmd/neverlauncher/runtime_commands.go")
require(commands, ['"forge-legacy-1.7.10"', '"forge-legacy-pre-1.7.10"', "legacy V1 universal installer"], "runtime capability status")

neverruntime = read("runtime/neverruntime/src/compatibility.rs")
require(neverruntime, [
    "metadata predates downloads.classifiers", "maven_path_with_classifier", "library.downloads.classifiers.is_empty()",
    '#[serde(default, alias = "clientreq")]', "library.client_req == Some(false)",
    "legacy_forge_native_classifier_without_downloads_is_resolved_from_maven_coordinate",
], "NeverRuntime 1.7.10 legacy resolution")

forge_case = read("e2e/scripts/run-forge-certification-case.sh")
require(forge_case, [
    "mc in ('1.7.10', '1.12.2')", "cpw.mods.fml.common.launcher.FMLTweaker", "legacyProfileNormalized",
    "legacyUniversalSha1", "legacyUniversalSha256", "certify-vanilla", "actual-mojang-client",
], "Forge 1.7.10 actual-client certification")

matrix = read("scripts/compatibility/matrix.py")
require(matrix, ["FORGE_LEGACY_1710_0175", "forge_legacy_1710_0175_required", "Forge Legacy 1.7.10 0.17.5"], "Forge 1.7.10 matrix")
release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, [
    "forgeLegacy1710_0175", "compatibilityForgeLegacy1710_0175Required",
    "forge-legacy-0.17.5-real-1.7.10-launchwrapper-cpw-fml-actual-client",
], "Forge 1.7.10 release certification")

tests = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
require(tests, [
    "test_validate_accepts_forge_legacy_1710_0175", "test_validate_rejects_missing_forge_legacy_1710_0175",
    "test_validate_rejects_wrong_forge_legacy_java_0175", "TestCompatibilityCertificationForgeLegacy1710_0175",
    "TestCompatibilityCertificationForgeLegacy1710_0175RejectsMissingTarget", "TestCompatibilityCertificationForgeLegacy1710_0175RejectsMutableResolvedLoader",
    "TestForgeLegacy1710V1LaunchWrapperInstaller", "TestCanonicalLegacyForgeRepositoryURL",
], "Forge 1.7.10 regression coverage")

print("Forge Legacy 1.7.10 0.17.5 gate: OK (real V1 universal + LaunchWrapper/cpw FML + Java 8 actual-client certification)")

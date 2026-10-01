#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 4):
    raise SystemExit(f"Forge Legacy 1.12.2 requires VERSION>=0.17.4, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")


matrix_globals = runpy.run_path(str(ROOT / "scripts/compatibility/matrix.py"))
expected = dict(matrix_globals["FORGE_LEGACY_1122_0174"])
if expected != {"1.12.2": 8}:
    raise SystemExit(f"Forge Legacy 0.17.4 canonical grid mismatch: {expected}")

target_doc = json.loads(read("compatibility/targets.json"))
rows = [row for row in target_doc["targets"] if row.get("required") and row.get("loader") == "forge" and row.get("minecraft") == "1.12.2"]
if len(rows) != 1:
    raise SystemExit(f"Forge Legacy 0.17.4 requires exactly one Forge 1.12.2 target, got {len(rows)}")
row = rows[0]
if row.get("javaMajor") != 8 or row.get("scope") != "client" or row.get("os") != "linux" or row.get("arch") != "x86_64":
    raise SystemExit("Forge Legacy 1.12.2 must be Java 8 client linux/x86_64")
if row.get("loaderVersion") != "latest-stable":
    raise SystemExit("Forge Legacy 1.12.2 must use latest-stable selector with immutable resolved evidence")

runtime = read("cli/cmd/neverlauncher/forge_runtime.go")
require(runtime, [
    "forgeLegacyInstallerProfile", "legacy-v1-universal", "legacy-v2-empty-processors", "installForgeLegacy",
    "install.filePath", "versionInfo", "net.minecraft.launchwrapper.Launch", "net.minecraftforge.fml.common.launcher.FMLTweaker",
    "extractInstallerEntry", "verifyForgeLegacyUniversal", "Checksums", "ClientReq", "legacyUniversalSha1", "legacyUniversalSha256",
], "Forge legacy materializer")

commands = read("cli/cmd/neverlauncher/runtime_commands.go")
require(commands, [
    '"forge-legacy-1.12.2"', '"forge-legacy-pre-1.12.2"', "legacy V1 universal installer",
], "runtime capability status")

neverruntime = read("runtime/neverruntime/src/compatibility.rs")
require(neverruntime, [
    '#[serde(default, alias = "clientreq")]', "client_req: Option<bool>", "library.client_req == Some(false)",
], "NeverRuntime legacy client library semantics")

forge_case = read("e2e/scripts/run-forge-certification-case.sh")
require(forge_case, [
    "mc == '1.12.2'", "legacy-v1-universal", "legacy-v2-empty-processors", "legacyUniversalPath",
    "legacyUniversalSha1", "legacyUniversalSha256", "net.minecraft.launchwrapper.Launch", "certify-vanilla",
    "resolvedLoaderVersion", "actual-mojang-client",
], "Forge legacy actual-client certification")

matrix = read("scripts/compatibility/matrix.py")
require(matrix, ["FORGE_LEGACY_1122_0174", "forge_legacy_1122_0174_required", "Forge Legacy 1.12.2 0.17.4"], "Forge legacy matrix")
release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, [
    "forgeLegacy1122_0174", "compatibilityForgeLegacy1122_0174Required",
    "forge-legacy-0.17.4-real-1.12.2-universal-fmltweaker-actual-client", "immutable version",
], "Forge legacy release certification")

tests = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
require(tests, [
    "test_validate_accepts_forge_legacy_1122_0174", "test_validate_rejects_missing_forge_legacy_1122_0174",
    "test_validate_rejects_wrong_forge_legacy_java_0174", "TestCompatibilityCertificationForgeLegacy1122_0174",
    "TestCompatibilityCertificationForgeLegacy1122_0174RejectsMissingTarget", "TestCompatibilityCertificationForgeLegacy1122_0174RejectsMutableResolvedLoader",
    "TestForgeLegacy1122V1UniversalInstaller", "TestForgeLegacy1122RepackedEmptyProcessorInstaller",
], "Forge legacy regression coverage")

print("Forge Legacy 1.12.2 0.17.4 gate: OK (real V1 universal installer + repacked empty-processor fallback + Java 8 actual-client certification)")

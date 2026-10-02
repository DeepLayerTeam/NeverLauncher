#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 6):
    raise SystemExit(f"NeoForge Compatibility II requires VERSION>=0.17.6, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")


matrix_globals = runpy.run_path(str(ROOT / "scripts/compatibility/matrix.py"))
expected: dict[str, int] = dict(matrix_globals["NEOFORGE_COMPATIBILITY_II_0176"])
if len(expected) != 22 or expected.get("1.20.1") != 17 or expected.get("1.20.5") != 21 or expected.get("26.2") != 25 or "26.3" in expected:
    raise SystemExit("NeoForge Compatibility II 0.17.6 canonical stable release grid is incomplete or includes unsupported 26.3")

target_doc = json.loads(read("compatibility/targets.json"))
rows = [row for row in target_doc["targets"] if row.get("required") and row.get("loader") == "neoforge" and row.get("os") == "linux" and row.get("arch") == "x86_64"]
if len(rows) != len(expected):
    raise SystemExit(f"NeoForge Compatibility II 0.17.6 requires exactly {len(expected)} required targets, got {len(rows)}")
by_version: dict[str, dict] = {}
for row in rows:
    minecraft = row.get("minecraft")
    if minecraft in by_version:
        raise SystemExit(f"NeoForge Compatibility II 0.17.6 duplicate Minecraft target: {minecraft}")
    by_version[minecraft] = row
if set(by_version) != set(expected):
    raise SystemExit(f"NeoForge Compatibility II 0.17.6 grid mismatch: missing={sorted(set(expected)-set(by_version))} extra={sorted(set(by_version)-set(expected))}")
for minecraft, java_major in expected.items():
    row = by_version[minecraft]
    expected_scope = "integration" if minecraft == "1.21.1" else "client"
    if row.get("javaMajor") != java_major or row.get("scope") != expected_scope:
        raise SystemExit(f"NeoForge {minecraft} must be Java {java_major} scope={expected_scope}")
    if row.get("os") != "linux" or row.get("arch") != "x86_64" or row.get("loaderVersion") != "latest-stable":
        raise SystemExit(f"NeoForge {minecraft} must be linux/x86_64 with runtime latest-stable resolution")

runtime = read("cli/cmd/neverlauncher/forge_runtime.go")
require(runtime, [
    'legacyNeoForge1201 := loader == "neoforge" && minecraftVersion == "1.20.1"',
    '/net/neoforged/forge/maven-metadata.xml', '/net/neoforged/neoforge/maven-metadata.xml',
    'neoForgeVersionMatchesMinecraft', '26.1 -> 26.1.0.x',
    'forgeInstallerURL(loader, vanilla.MinecraftVersion, artifactVersion)',
    '/net/neoforged/forge/%s/forge-%s-installer.jar',
    '/net/neoforged/neoforge/%s/neoforge-%s-installer.jar',
    'clientProcessorCount', 'runForgeProcessors', 'installed-and-verified',
], "NeoForge production materializer")

case = read("e2e/scripts/run-neoforge-certification-case.sh")
require(case, [
    'runtime neoforge-package', 'client verify', 'neoforge-install.json', 'neoforge-certification.json',
    "mode != 'processors'", 'clientProcessorCount', 'processorRan', 'processorSkipped',
    'installerSha256', 'profileSha256', 'certify-vanilla', 'mutable loader selector leaked',
    "'loader': 'neoforge'", "'actualClient': True",
], "NeoForge actual-client certification")

compat = read("e2e/scripts/run-compatibility-case.sh")
require(compat, [
    '"$LOADER" == "neoforge"', 'run-neoforge-certification-case.sh',
    'loader in ("fabric", "quilt", "forge", "neoforge")',
], "NeoForge compatibility routing")

matrix = read("scripts/compatibility/matrix.py")
require(matrix, [
    'NEOFORGE_COMPATIBILITY_II_0176', 'neoforge_compatibility_ii_0176_required',
    'NeoForge Compatibility II 0.17.6',
], "NeoForge matrix enforcement")

release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, [
    'neoForgeCompatibilityII0176', 'compatibilityNeoForgeII0176Required', 'NeoForgeVersions',
    'neoforge-compatibility-II-0.17.6-stable-1.20.1-through-26.2-processor-actual-client',
], "NeoForge release certification")

api = read("services/api/internal/httpapi/server.go")
require(api, [
    '{"id": "neoforge", "name": "NeoForge", "resolution": "inherited-version-json", "adapter": "compatibility-engine", "installer": "neverlauncher-neoforge-materializer", "managedJava": true}',
], "NeoForge public loader catalog")

workflow = read(".github/workflows/compatibility.yml")
require(workflow, ['neoforge-install.json', 'neoforge-certification.json'], "NeoForge CI raw evidence")

tests = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
require(tests, [
    'test_validate_accepts_neoforge_compatibility_ii_0176',
    'test_validate_rejects_missing_neoforge_release_0176',
    'test_validate_rejects_wrong_neoforge_java_0176',
    'test_validate_rejects_duplicate_neoforge_release_0176',
    'TestCompatibilityCertificationNeoForgeII0176',
    'TestCompatibilityCertificationNeoForgeII0176RejectsMissingRelease',
    'TestCompatibilityCertificationNeoForgeII0176RejectsWrongJavaMajor',
    'TestCompatibilityCertificationNeoForgeII0176RejectsMutableResolvedLoader',
    'TestCompatibilityCertificationNeoForgeII0176BundleRejectsTamperedCoverage',
    '26.2.0.75', '1.20.1-47.1.79',
], "NeoForge 0.17.6 regression coverage")

print(f"NeoForge Compatibility II 0.17.6 gate: OK ({len(rows)} stable NeoForge releases, 1.20.1..26.2, Java 17/21/25)")

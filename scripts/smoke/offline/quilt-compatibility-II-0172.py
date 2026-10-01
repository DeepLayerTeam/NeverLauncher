#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 2):
    raise SystemExit(f"Quilt Compatibility II requires VERSION>=0.17.2, got {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: missing {missing}")


matrix_globals = runpy.run_path(str(ROOT / "scripts/compatibility/matrix.py"))
expected: dict[str, int] = dict(matrix_globals["QUILT_COMPATIBILITY_II_0172"])
if len(expected) != 48 or expected.get("1.14") != 8 or expected.get("1.17") != 16 or expected.get("1.20.5") != 21 or expected.get("26.3") != 25:
    raise SystemExit("Quilt 0.17.2 canonical release grid is incomplete")

target_doc = json.loads(read("compatibility/targets.json"))
quilt_rows = [row for row in target_doc["targets"] if row.get("required") and row.get("loader") == "quilt"]
if len(quilt_rows) != len(expected):
    raise SystemExit(f"Quilt 0.17.2 requires exactly {len(expected)} required targets, got {len(quilt_rows)}")
by_version: dict[str, dict] = {}
for row in quilt_rows:
    minecraft = row.get("minecraft")
    if minecraft in by_version:
        raise SystemExit(f"Quilt 0.17.2 duplicate Minecraft target: {minecraft}")
    by_version[minecraft] = row
if set(by_version) != set(expected):
    raise SystemExit(f"Quilt 0.17.2 release grid mismatch: missing={sorted(set(expected)-set(by_version))} extra={sorted(set(by_version)-set(expected))}")
for minecraft, java_major in expected.items():
    row = by_version[minecraft]
    expected_scope = "integration" if minecraft == "1.21.1" else "client"
    if row.get("javaMajor") != java_major or row.get("scope") != expected_scope:
        raise SystemExit(f"Quilt {minecraft} must be Java {java_major} scope={expected_scope}")
    if row.get("os") != "linux" or row.get("arch") != "x86_64":
        raise SystemExit(f"Quilt {minecraft} must be certified on linux/x86_64")
    if row.get("loaderVersion") != "latest-stable":
        raise SystemExit(f"Quilt {minecraft} must resolve latest-stable at execution time")

loader_runtime = read("cli/cmd/neverlauncher/loader_runtime.go")
require(loader_runtime, [
    'defaultQuiltMetaBase  = "https://meta.quiltmc.org/v3"',
    "isStableQuiltLoaderVersion", "стабильную %s loader version", "profile/json",
    "materializeLoaderLibraries", "installed-and-verified",
], "Quilt materializer/runtime resolution")

quilt_case = read("e2e/scripts/run-quilt-certification-case.sh")
require(quilt_case, [
    "runtime quilt-package", "client verify", "quilt-install.json", "quilt-certification.json",
    "loaderVersion", "profileId", "mainClass", "libraryCount", "certify-vanilla",
    "resolvedLoaderVersion", "mutable loader selector leaked", "actual-mojang-client",
], "Quilt actual-client certification")

compat_case = read("e2e/scripts/run-compatibility-case.sh")
require(compat_case, [
    '"$LOADER" == "quilt"', "run-quilt-certification-case.sh", 'loader in ("fabric", "quilt")',
    'install_name = f"{loader}-install.json"', 'probe_name = f"{loader}-certification.json"',
    "resolvedLoaderVersion", '"actualClient": probe.get("status") == "passed"',
], "Quilt compatibility routing/evidence")

matrix = read("scripts/compatibility/matrix.py")
require(matrix, [
    "QUILT_COMPATIBILITY_II_0172", "quilt_compatibility_ii_0172_required", "Quilt Compatibility II 0.17.2",
    'target["loader"] in {"fabric", "quilt"}', 'install_file = f"{target[\'loader\']}-install.json"',
    'certification_file = f"{target[\'loader\']}-certification.json"',
], "Quilt matrix enforcement")

release = read("cli/cmd/neverlauncher/compatibility_release.go")
require(release, [
    "quiltCompatibilityII0172", "compatibilityQuiltII0172Required", "QuiltVersions",
    "quilt-compatibility-II-0.17.2-stable-1.14-through-current-actual-client", "immutable version",
], "Quilt release certification")

workflow = read(".github/workflows/compatibility.yml")
require(workflow, [
    "run-compatibility-case.sh", "quilt-install.json", "quilt-certification.json",
], "Quilt CI raw evidence")

tests = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/loader_runtime_test.go")
require(tests, [
    "test_validate_accepts_quilt_compatibility_ii_0172_grid",
    "test_validate_rejects_missing_quilt_release_0172",
    "test_validate_rejects_wrong_quilt_java_0172",
    "test_validate_rejects_duplicate_quilt_release_0172",
    "TestCompatibilityCertificationQuiltII0172",
    "TestCompatibilityCertificationQuiltII0172RejectsMissingRelease",
    "TestCompatibilityCertificationQuiltII0172RejectsWrongJavaMajor",
    "TestCompatibilityCertificationQuiltII0172RejectsMutableResolvedLoader",
    "TestQuiltLatestStableSelectionUsesStableSemVerWhenMetaOmitsStableFlag",
    "TestQuiltLatestStableFailsClosedWhenMetaContainsOnlyPrereleases",
], "Quilt 0.17.2 regression coverage")

print(f"Quilt Compatibility II 0.17.2 gate: OK ({len(quilt_rows)} stable Quilt releases, 1.14..26.3, Java 8/16/17/21/25)")

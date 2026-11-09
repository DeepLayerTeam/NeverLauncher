#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 1):
    raise SystemExit(f"Fabric Compatibility II: требуется «VERSION>=0.17.1, got» {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


expected: dict[str, int] = {
    "1.14": 8,
    "1.14.1": 8,
    "1.14.2": 8,
    "1.14.3": 8,
    "1.14.4": 8,
    "1.15": 8,
    "1.15.1": 8,
    "1.15.2": 8,
    "1.16": 8,
    "1.16.1": 8,
    "1.16.2": 8,
    "1.16.3": 8,
    "1.16.4": 8,
    "1.16.5": 8,
    "1.17": 16,
    "1.17.1": 16,
    "1.18": 17,
    "1.18.1": 17,
    "1.18.2": 17,
    "1.19": 17,
    "1.19.1": 17,
    "1.19.2": 17,
    "1.19.3": 17,
    "1.19.4": 17,
    "1.20": 17,
    "1.20.1": 17,
    "1.20.2": 17,
    "1.20.3": 17,
    "1.20.4": 17,
    "1.20.5": 21,
    "1.20.6": 21,
    "1.21": 21,
    "1.21.1": 21,
    "1.21.2": 21,
    "1.21.3": 21,
    "1.21.4": 21,
    "1.21.5": 21,
    "1.21.6": 21,
    "1.21.7": 21,
    "1.21.8": 21,
    "1.21.9": 21,
    "1.21.10": 21,
    "1.21.11": 21,
    "26.1": 25,
    "26.1.1": 25,
    "26.1.2": 25,
    "26.2": 25,
    "26.3": 25,
}

target_doc = json.loads(read("compatibility/targets.json"))
fabric_rows = [
    row
    for row in target_doc["targets"]
    if row.get("required")
    and row.get("loader") == "fabric"
    and row.get("os") == "linux"
    and row.get("arch") == "x86_64"
]
if len(fabric_rows) != len(expected):
    raise SystemExit(
        f"Fabric 0.17.1: требуется ровно {len(expected)} required targets, получено {len(fabric_rows)}"
    )
by_version: dict[str, dict] = {}
for row in fabric_rows:
    minecraft = row.get("minecraft")
    if minecraft in by_version:
        raise SystemExit(f"Fabric 0.17.1: повторяющаяся цель Minecraft: {minecraft}")
    by_version[minecraft] = row
if set(by_version) != set(expected):
    raise SystemExit(
        f"Fabric 0.17.1 матрица релизов: несоответствие — отсутствуют={sorted(set(expected) - set(by_version))} лишние={sorted(set(by_version) - set(expected))}"
    )
for minecraft, java_major in expected.items():
    row = by_version[minecraft]
    expected_scope = "integration" if minecraft == "1.21.1" else "client"
    if row.get("javaMajor") != java_major or row.get("scope") != expected_scope:
        raise SystemExit(
            f"Fabric {minecraft} должен использовать Java {java_major}, область={expected_scope}"
        )
    if row.get("os") != "linux" or row.get("arch") != "x86_64":
        raise SystemExit(f"Для Fabric {minecraft} требуется сертификация на linux/x86_64")
    if row.get("loaderVersion") != "latest-stable":
        raise SystemExit(
            f"Для Fabric {minecraft} последняя стабильная версия должна определяться во время выполнения"
        )

fabric_case = read("e2e/scripts/run-fabric-certification-case.sh")
require(
    fabric_case,
    [
        "runtime fabric-package",
        "client verify",
        "fabric-install.json",
        "fabric-certification.json",
        "loaderVersion",
        "profileId",
        "mainClass",
        "libraryCount",
        "certify-vanilla",
        "resolvedLoaderVersion",
        "mutable loader selector leaked",
        "actual-mojang-client",
    ],
    "Сертификация на настоящем клиенте Fabric",
)

compat_case = read("e2e/scripts/run-compatibility-case.sh")
require(
    compat_case,
    [
        '"$LOADER" == "fabric"',
        "run-fabric-certification-case.sh",
        'loader in ("fabric", "quilt", "forge", "neoforge")',
        'install_name = f"{loader}-install.json"',
        'probe_name = f"{loader}-certification.json"',
        "resolvedLoaderVersion",
        '"actualClient": probe.get("status") == "passed"',
    ],
    "Маршрутизация и свидетельства совместимости Fabric",
)

matrix = read("scripts/compatibility/matrix.py")
require(
    matrix,
    [
        "FABRIC_COMPATIBILITY_II_0171",
        "fabric_compatibility_ii_0171_required",
        "Fabric Compatibility II 0.17.1",
        'target["loader"] in {"fabric", "quilt", "forge", "neoforge"}',
        "install_file = f\"{target['loader']}-install.json\"",
        "certification_file = f\"{target['loader']}-certification.json\"",
    ],
    "Обязательные проверки матрицы Fabric",
)

release = read("cli/cmd/launcher/compatibility_release.go")
require(
    release,
    [
        "fabricCompatibilityII0171",
        "compatibilityFabricII0171Required",
        "FabricVersions",
        "fabric-compatibility-II-0.17.1-stable-1.14-through-current-actual-client",
        "immutable version",
    ],
    "Сертификация релиза Fabric",
)

workflow = read(".github/workflows/compatibility.yml")
require(
    workflow,
    [
        "run-compatibility-case.sh",
        "fabric-install.json",
        "fabric-certification.json",
    ],
    "Исходные свидетельства проверки Fabric в CI",
)

tests = read("scripts/compatibility/test_matrix.py") + read(
    "cli/cmd/launcher/compatibility_release_test.go"
)
require(
    tests,
    [
        "test_validate_accepts_fabric_compatibility_ii_0171_grid",
        "test_validate_rejects_missing_fabric_release_0171",
        "test_validate_rejects_wrong_fabric_java_0171",
        "test_validate_rejects_duplicate_fabric_release_0171",
        "TestCompatibilityCertificationFabricII0171",
        "TestCompatibilityCertificationFabricII0171RejectsMissingRelease",
        "TestCompatibilityCertificationFabricII0171RejectsWrongJavaMajor",
        "TestCompatibilityCertificationFabricII0171RejectsMutableResolvedLoader",
    ],
    "Покрытие регрессионными тестами Fabric 0.17.1",
)

print(
    f"Проверка совместимости Fabric II 0.17.1: OK ({len(fabric_rows)} стабильных релизов Fabric, 1.14..26.3, Java 8/16/17/21/25)"
)

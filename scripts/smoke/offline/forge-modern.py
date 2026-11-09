#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 3):
    raise SystemExit(f"Forge Modern: требуется «VERSION>=0.17.3, got» {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


matrix_globals = runpy.run_path(str(ROOT / "scripts/compatibility/matrix.py"))
expected: dict[str, int] = dict(matrix_globals["FORGE_MODERN_0173"])
if (
    len(expected) != 43
    or expected.get("1.13.2") != 8
    or expected.get("1.17.1") != 16
    or expected.get("1.20.6") != 21
    or expected.get("26.3") != 25
):
    raise SystemExit(
        "Forge Modern 0.17.3 canonical processor-based release grid: проверка или реализация не завершена"
    )

target_doc = json.loads(read("compatibility/targets.json"))
forge_rows = [
    row
    for row in target_doc["targets"]
    if row.get("required")
    and row.get("loader") == "forge"
    and row.get("minecraft") in expected
    and row.get("os") == "linux"
    and row.get("arch") == "x86_64"
]
if len(forge_rows) != len(expected):
    raise SystemExit(
        f"Forge Modern 0.17.3: требуется ровно {len(expected)} required targets, получено {len(forge_rows)}"
    )
by_version: dict[str, dict] = {}
for row in forge_rows:
    minecraft = row.get("minecraft")
    if minecraft in by_version:
        raise SystemExit(f"Forge Modern 0.17.3: повторяющаяся цель Minecraft: {minecraft}")
    by_version[minecraft] = row
if set(by_version) != set(expected):
    raise SystemExit(
        f"Forge Modern 0.17.3 матрица релизов: несоответствие — отсутствуют={sorted(set(expected) - set(by_version))} лишние={sorted(set(by_version) - set(expected))}"
    )
for minecraft, java_major in expected.items():
    row = by_version[minecraft]
    expected_scope = "integration" if minecraft == "1.21.1" else "client"
    if row.get("javaMajor") != java_major or row.get("scope") != expected_scope:
        raise SystemExit(
            f"Forge {minecraft} должен использовать Java {java_major}, область={expected_scope}"
        )
    if row.get("os") != "linux" or row.get("arch") != "x86_64":
        raise SystemExit(f"Для Forge {minecraft} требуется сертификация на linux/x86_64")
    if row.get("loaderVersion") != "latest-stable":
        raise SystemExit(
            f"Для Forge {minecraft} последняя стабильная версия должна определяться во время выполнения"
        )

runtime = read("cli/cmd/launcher/forge_runtime.go")
require(
    runtime,
    [
        "installForgeLike",
        "runForgeProcessors",
        "clientProcessorCount",
        "processor-based modern installer format",
        "MINECRAFT_VERSION",
        "INSTALLER",
        "LIBRARY_DIR",
        "resolveProcessorNamedToken",
        "resolveInstallerDataValue",
        "extractInstallerData",
        "installerSha256",
        "profileSha256",
        "installed-and-verified",
    ],
    "Установщик компонентов обработки Forge",
)

forge_case = read("e2e/scripts/run-forge-certification-case.sh")
require(
    forge_case,
    [
        "runtime forge-package",
        "--java",
        "client verify",
        "forge-install.json",
        "forge-certification.json",
        "clientProcessorCount",
        "processorRan",
        "processorSkipped",
        "installerSha256",
        "profileSha256",
        "certify-vanilla",
        "resolvedLoaderVersion",
        "mutable loader selector leaked",
        "actual-mojang-client",
    ],
    "Сертификация на настоящем клиенте Forge",
)

compat_case = read("e2e/scripts/run-compatibility-case.sh")
require(
    compat_case,
    [
        '"$LOADER" == "forge"',
        "run-forge-certification-case.sh",
        'loader in ("fabric", "quilt", "forge", "neoforge")',
        'install_name = f"{loader}-install.json"',
        'probe_name = f"{loader}-certification.json"',
        "resolvedLoaderVersion",
        '"actualClient": probe.get("status") == "passed"',
    ],
    "Маршрутизация и свидетельства совместимости Forge",
)

matrix = read("scripts/compatibility/matrix.py")
require(
    matrix,
    [
        "FORGE_MODERN_0173",
        "forge_modern_0173_required",
        "Forge Modern 0.17.3",
        'target["loader"] in {"fabric", "quilt", "forge", "neoforge"}',
        "install_file = f\"{target['loader']}-install.json\"",
        "certification_file = f\"{target['loader']}-certification.json\"",
    ],
    "Обязательные проверки матрицы Forge",
)

release = read("cli/cmd/launcher/compatibility_release.go")
require(
    release,
    [
        "forgeModern0173",
        "compatibilityForgeModern0173Required",
        "ForgeVersions",
        "forge-modern-0.17.3-processor-based-1.13.2-through-current-actual-client",
        "immutable version",
    ],
    "Сертификация релиза Forge",
)

api_catalog = read("services/api/internal/httpapi/server.go")
require(
    api_catalog,
    [
        '{"id": "forge", "name": "Forge", "resolution": "inherited-version-json", "adapter": "compatibility-engine", "installer": "launcher-forge-materializer", "managedJava": true}',
    ],
    "Публичный каталог загрузчика Forge",
)

workflow = read(".github/workflows/compatibility.yml")
require(
    workflow,
    [
        "run-compatibility-case.sh",
        "forge-install.json",
        "forge-certification.json",
    ],
    "Исходные свидетельства проверки Forge в CI",
)

tests = (
    read("scripts/compatibility/test_matrix.py")
    + read("cli/cmd/launcher/compatibility_release_test.go")
    + read("cli/cmd/launcher/forge_runtime_test.go")
)
require(
    tests,
    [
        "test_validate_accepts_forge_modern_0173_grid",
        "test_validate_rejects_missing_forge_release_0173",
        "test_validate_rejects_wrong_forge_java_0173",
        "test_validate_rejects_duplicate_forge_release_0173",
        "TestCompatibilityCertificationForgeModern0173",
        "TestCompatibilityCertificationForgeModern0173RejectsMissingRelease",
        "TestCompatibilityCertificationForgeModern0173RejectsWrongJavaMajor",
        "TestCompatibilityCertificationForgeModern0173RejectsMutableResolvedLoader",
        "TestForgeInstallV1ProcessorTokens",
    ],
    "Покрытие регрессионными тестами Forge 0.17.3",
)

print(
    f"Проверка современного Forge 0.17.3: OK ({len(forge_rows)} релизов Forge с обработчиками, 1.13.2..26.3, Java 8/16/17/21/25)"
)

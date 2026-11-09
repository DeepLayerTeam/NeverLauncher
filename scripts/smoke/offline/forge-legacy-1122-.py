#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 4):
    raise SystemExit(f"Forge Legacy 1.12.2: требуется версия не ниже 0.17.4, получено {version}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


matrix_globals = runpy.run_path(str(ROOT / "scripts/compatibility/matrix.py"))
expected = dict(matrix_globals["FORGE_LEGACY_1122_0174"])
if expected != {"1.12.2": 8}:
    raise SystemExit(f"Несовпадение: «каноническая матрица Forge Legacy 0.17.4»: {expected}")

target_doc = json.loads(read("compatibility/targets.json"))
rows = [
    row
    for row in target_doc["targets"]
    if row.get("required")
    and row.get("loader") == "forge"
    and row.get("minecraft") == "1.12.2"
]
if len(rows) != 1:
    raise SystemExit(
        f"Forge Legacy 0.17.4: требуется ровно one Forge 1.12.2 target, получено {len(rows)}"
    )
row = rows[0]
if (
    row.get("javaMajor") != 8
    or row.get("scope") != "client"
    or row.get("os") != "linux"
    or row.get("arch") != "x86_64"
):
    raise SystemExit("Forge Legacy 1.12.2: требуется «клиент Java 8 для Linux/x86_64»")
if row.get("loaderVersion") != "latest-stable":
    raise SystemExit(
        "Устаревший Forge 1.12.2 должен выбирать последнюю стабильную версию с неизменяемым подтверждением разрешения"
    )

runtime = read("cli/cmd/launcher/forge_runtime.go")
require(
    runtime,
    [
        "forgeLegacyInstallerProfile",
        "legacy-v1-universal",
        "legacy-v2-empty-processors",
        "installForgeLegacy",
        "install.filePath",
        "versionInfo",
        "net.minecraft.launchwrapper.Launch",
        "net.minecraftforge.fml.common.launcher.FMLTweaker",
        "extractInstallerEntry",
        "verifyForgeLegacyUniversal",
        "Checksums",
        "ClientReq",
        "legacyUniversalSha1",
        "legacyUniversalSha256",
    ],
    "Установщик устаревших версий Forge",
)

commands = read("cli/cmd/launcher/runtime_commands.go")
require(
    commands,
    [
        '"forge-legacy-1.12.2"',
        "legacy V1 universal installer",
    ],
    "Состояние возможностей Runtime",
)

runtime = read("runtime/runtime/src/compatibility.rs")
require(
    runtime,
    [
        '#[serde(default, alias = "clientreq")]',
        "client_req: Option<bool>",
        "library.client_req == Some(false)",
    ],
    "Совместимость Runtime со старыми клиентскими библиотеками",
)

forge_case = read("e2e/scripts/run-forge-certification-case.sh")
require(
    forge_case,
    [
        "mc in ('1.7.10', '1.12.2')",
        "legacy-v1-universal",
        "legacy-v2-empty-processors",
        "legacyUniversalPath",
        "legacyUniversalSha1",
        "legacyUniversalSha256",
        "net.minecraft.launchwrapper.Launch",
        "certify-vanilla",
        "resolvedLoaderVersion",
        "actual-mojang-client",
    ],
    "Сертификация старого Forge на настоящем клиенте",
)

matrix = read("scripts/compatibility/matrix.py")
require(
    matrix,
    [
        "FORGE_LEGACY_1122_0174",
        "forge_legacy_1122_0174_required",
        "Forge Legacy 1.12.2 0.17.4",
    ],
    "Матрица старых версий Forge",
)
release = read("cli/cmd/launcher/compatibility_release.go")
require(
    release,
    [
        "forgeLegacy1122_0174",
        "compatibilityForgeLegacy1122_0174Required",
        "forge-legacy-0.17.4-real-1.12.2-universal-fmltweaker-actual-client",
        "immutable version",
    ],
    "Сертификация релиза старых версий Forge",
)

tests = (
    read("scripts/compatibility/test_matrix.py")
    + read("cli/cmd/launcher/compatibility_release_test.go")
    + read("cli/cmd/launcher/forge_runtime_test.go")
)
require(
    tests,
    [
        "test_validate_accepts_forge_legacy_1122_0174",
        "test_validate_rejects_missing_forge_legacy_1122_0174",
        "test_validate_rejects_wrong_forge_legacy_java_0174",
        "TestCompatibilityCertificationForgeLegacy1122_0174",
        "TestCompatibilityCertificationForgeLegacy1122_0174RejectsMissingTarget",
        "TestCompatibilityCertificationForgeLegacy1122_0174RejectsMutableResolvedLoader",
        "TestForgeLegacy1122V1UniversalInstaller",
        "TestForgeLegacy1122RepackedEmptyProcessorInstaller",
    ],
    "Покрытие старых версий Forge регрессионными тестами",
)

print(
    "Проверка устаревшего Forge 1.12.2 версии 0.17.4: OK (универсальный установщик V1, резервная обработка переупакованного архива без обработчиков, сертификация реального клиента Java 8)"
)

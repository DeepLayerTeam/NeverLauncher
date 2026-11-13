#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = tuple(int(p) for p in version.split("-")[0].split("+")[0].split(".")[:3])
if core < (0, 17, 0):
    raise SystemExit(
        f"Minecraft Compatibility II GA: требуется версия не ниже 0.17.0, получено {version}"
    )


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, tokens: list[str], name: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name}: отсутствует {missing}")


targets = json.loads(read("compatibility/targets.json"))
vanilla = [
    row
    for row in targets["targets"]
    if row.get("required") and row.get("loader") == "vanilla"
]
if len(vanilla) < 109 or len({row["minecraft"] for row in vanilla}) < 104:
    raise SystemExit(
        "Базовое покрытие Vanilla для GA 0.17.0v3 меньше 109 целей и 104 уникальных релизов"
    )
if {8, 16, 17, 21, 25} - {row["javaMajor"] for row in vanilla}:
    raise SystemExit("Базовый набор JRE для GA не покрывает Java 8/16/17/21/25")

legacy_0170v1 = {
    "1.2.1",
    "1.2.2",
    "1.2.3",
    "1.2.4",
    "1.3.1",
    "1.4.2",
    "1.4.4",
    "1.4.5",
    "1.4.6",
    "1.5",
    "1.5.1",
    "1.6.1",
    "1.6.2",
    "1.7.2",
    "1.7.3",
    "1.7.4",
    "1.7.5",
    "1.7.6",
    "1.7.7",
    "1.7.8",
    "1.7.9",
    "1.8",
    "1.8.1",
    "1.8.2",
    "1.8.3",
    "1.8.4",
    "1.8.5",
    "1.8.6",
    "1.8.7",
    "1.8.8",
    "1.9",
    "1.9.1",
    "1.9.2",
    "1.9.3",
    "1.10",
    "1.10.1",
    "1.11",
    "1.11.1",
    "1.12",
    "1.12.1",
    "1.13",
    "1.13.1",
    "1.14",
    "1.14.1",
    "1.14.2",
    "1.14.3",
    "1.15",
    "1.15.1",
    "1.16",
    "1.16.1",
    "1.16.2",
    "1.16.3",
    "1.16.4",
}
legacy_rows = {
    row["minecraft"]: row
    for row in vanilla
    if row["minecraft"] in legacy_0170v1
    and row["os"] == "linux"
    and row["arch"] == "x86_64"
}
missing_legacy = sorted(legacy_0170v1 - set(legacy_rows))
if missing_legacy:
    raise SystemExit(
        f"GA 0.17.0v1: в полной матрице старых версий Vanilla отсутствует {missing_legacy}"
    )
for minecraft, row in legacy_rows.items():
    if row["javaMajor"] != 8 or row["scope"] != "client":
        raise SystemExit(
            f"Устаревший Vanilla {minecraft} для GA 0.17.0v1 должен использовать Java 8, область=клиент"
        )

java16_17_0170v2 = {
    "1.17": 16,
    "1.18": 17,
    "1.18.1": 17,
    "1.19": 17,
    "1.19.1": 17,
    "1.19.2": 17,
    "1.19.3": 17,
    "1.20": 17,
    "1.20.3": 17,
}
modern_rows = {
    row["minecraft"]: row
    for row in vanilla
    if row["minecraft"] in java16_17_0170v2
    and row["os"] == "linux"
    and row["arch"] == "x86_64"
}
missing_modern = sorted(set(java16_17_0170v2) - set(modern_rows))
if missing_modern:
    raise SystemExit(
        f"GA 0.17.0v2 complete Java 16/17 Vanilla grid: отсутствует {missing_modern}"
    )
for minecraft, major in java16_17_0170v2.items():
    row = modern_rows[minecraft]
    if row["javaMajor"] != major or row["scope"] != "client":
        raise SystemExit(
            f"Vanilla {minecraft} для GA 0.17.0v2 должен использовать Java {major}, область=клиент"
        )

java21_25_0170v3 = {"1.21.11": 21, "26.2": 25}
v3_rows = {
    row["minecraft"]: row
    for row in vanilla
    if row["minecraft"] in java21_25_0170v3
    and row["os"] == "linux"
    and row["arch"] == "x86_64"
}
missing_v3 = sorted(set(java21_25_0170v3) - set(v3_rows))
if missing_v3:
    raise SystemExit(f"Отсутствует: «матрица Vanilla Java 21/25 для GA 0.17.0v3»: {missing_v3}")
for minecraft, major in java21_25_0170v3.items():
    row = v3_rows[minecraft]
    if row["javaMajor"] != major or row["scope"] != "client":
        raise SystemExit(
            f"Vanilla {minecraft} для GA 0.17.0v3 должен использовать Java {major}, область=клиент"
        )

require(
    read("scripts/compatibility/certify-jre.py"),
    [
        "executableSha256",
        "java.runtime.version",
        "java.vendor",
        "java.vm.name",
        "java.home",
        "detectedOS",
        "detectedArch",
        "certified",
    ],
    "Аттестация среды Java",
)
require(
    read("e2e/scripts/run-compatibility-case.sh"),
    [
        "certify-jre.py",
        '"jreCertified"',
        '"jreVendor"',
        '"jreRuntimeVersion"',
        '"jreExecutableSha256"',
    ],
    "Привязка целевой совместимости к JRE",
)
require(
    read("scripts/compatibility/matrix.py"),
    [
        "LEGACY_VANILLA_0170V1",
        "JAVA16_17_VANILLA_0170V2",
        "JAVA21_25_VANILLA_0170V3",
        "COMPATIBILITY_II_GA_MIN_UNIQUE_VANILLA",
        "jreCertified",
        "build_ga_jre_base",
        '"jreBase"',
    ],
    "Объединение результатов матрицы GA",
)
require(
    read("cli/cmd/launcher/compatibility_release.go"),
    [
        "compatibilityLegacyVanilla0170v1Required",
        "compatibilityJava16_17Vanilla0170v2Required",
        "compatibilityJava21_25Vanilla0170v3Required",
        "compatibilityIIGa0170Required",
        "JREExecutableSHA256",
        "JREBuilds",
        "legacy-vanilla-0.17.0v1-complete-53-release-grid-java8",
        "java16-17-vanilla-0.17.0v2-complete-9-release-grid-exact",
        "java21-25-vanilla-0.17.0v3-complete-2-release-grid-exact",
        "minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base",
    ],
    "Сертификация релиза GA",
)
require(
    read("cli/cmd/launcher/vanilla_runtime.go"),
    [
        "legacyVanilla0170v1Releases",
        "java16_17Vanilla0170v2Releases",
        "java21_25Vanilla0170v3Releases",
        "expectedJavaMajorForVanilla0170v2",
        "expectedJavaMajorForVanilla0170v3",
        "validateVanillaLaunchMetadata",
    ],
    "Установщик Vanilla для GA 0.17.0v3",
)
require(
    read("runtime/runtime/src/compatibility.rs"),
    [
        "Legacy Vanilla requires Java 8",
        "expected_java_major_for_vanilla_0170v2",
        "0.17.0v2 требуется точная версия Java",
        "expected_java_major_for_vanilla_0170v3",
        "0.17.0v3 требуется точная версия Java",
        "metadata does not contain executable arguments.game or minecraftArguments",
    ],
    "Выполнение Runtime GA 0.17.0v3",
)
require(
    read(".github/workflows/compatibility.yml"),
    ["java-runtime.json", "run-compatibility-case.sh"],
    "Свидетельства проверки GA в CI",
)
require(
    read("scripts/smoke/offline/compatibility-matrix.sh"),
    ["test_certify_jre.py"],
    "Регрессионная предварительная проверка GA",
)

print(
    f"Проверка совместимости Minecraft II GA 0.17.0: ПРОЙДЕНА / 0.17.0v3 матрица Java 21/25 ({len(vanilla)} целевых платформ Vanilla, {len({row['minecraft'] for row in vanilla})} релизов, Java 8/16/17/21/25)"
)
print('Minecraft Compatibility II GA 0.17.0 gate: OK / 0.17.0v3 Java 21/25 grid')

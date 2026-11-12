#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 16, 5):
    raise SystemExit(f"Управляемая Java II: требуется версия не ниже 0.16.5, получено {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


runtime = read("runtime/runtime/src/managed_java.rs")
require(
    runtime,
    [
        "MANAGED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
        "assets/latest/{major}/hotspot",
        "assets/feature_releases/{major}/ga",
        'for image_type in ["jre", "jdk"]',
        "validate_managed_java_major",
        "archive_sha256",
        "ensure_archive",
        "validate_installed_runtime",
        "Путь к Java в записи среды выполнения выходит за пределы управляемой Java через символическую ссылку",
    ],
    "Managed Java II в Runtime",
)

runtime_cli = read("runtime/runtime/src/bin/runtime.rs")
require(
    runtime_cli,
    ["--major <8|16|17|21|25>", "ensure_managed_java"],
    "Командная строка Java Runtime",
)

e2e = read("e2e/scripts/run-managed-java-II-e2e.sh")
require(
    e2e,
    [
        "for major in 8 16 17 21 25",
        "java ensure",
        'assert data["cached"] is False',
        'assert second["cached"] is True',
        'subprocess.run([java, "-version"]',
        "MANAGED_JAVA_II_EVIDENCE.json",
    ],
    "Сквозная проверка исполняемой Managed Java II",
)

ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        "Managed Java II Java 8/16/17/21/25 production E2E",
        "run-managed-java-II-e2e.sh",
        "MANAGED_JAVA_II_EVIDENCE.json",
    ],
    "Подключение Managed Java II к CI",
)

preflight = read("scripts/release/preflight.sh")
require(preflight, ["managed-java-II-0165.py"], "Предварительная проверка управляемой среды Java II")

release = read("cli/cmd/launcher/release_commands.go")
require(release, ["managed-java-II-8-16-17-21-25"], "Обязательная проверка релиза Managed Java II")

subprocess.run(
    ["go", "test", "./cmd/launcher", "-run", "TestManagedJavaII", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"Launcher {VERSION}: проверка управляемой среды Java II: OK")

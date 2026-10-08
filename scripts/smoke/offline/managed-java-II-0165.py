#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 16, 5):
    raise SystemExit(f"Managed Java II gate requires VERSION>=0.16.5, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


runtime = read("runtime/neverruntime/src/managed_java.rs")
require(runtime, [
    "MANAGED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
    "assets/latest/{major}/hotspot",
    "assets/feature_releases/{major}/ga",
    'for image_type in ["jre", "jdk"]',
    "validate_managed_java_major",
    "archive_sha256",
    "ensure_archive",
    "validate_installed_runtime",
    "runtime record java path вышел за Managed Java root через symlink",
], "NeverRuntime Managed Java II")

runtime_cli = read("runtime/neverruntime/src/bin/neverruntime.rs")
require(runtime_cli, ["--major <8|16|17|21|25>", "ensure_managed_java"], "NeverRuntime Java CLI")

e2e = read("e2e/scripts/run-managed-java-II-e2e.sh")
require(e2e, [
    "for major in 8 16 17 21 25",
    "java ensure",
    'assert data["cached"] is False',
    'assert second["cached"] is True',
    'subprocess.run([java, "-version"]',
    "MANAGED_JAVA_II_EVIDENCE.json",
], "Managed Java II executable E2E")

ci = read(".github/workflows/ci.yml")
require(ci, [
    "Managed Java II Java 8/16/17/21/25 production E2E",
    "run-managed-java-II-e2e.sh",
    "MANAGED_JAVA_II_EVIDENCE.json",
], "Managed Java II CI wiring")

preflight = read("scripts/release/preflight.sh")
require(preflight, ["managed-java-II-0165.py"], "Managed Java II preflight")

release = read("cli/cmd/neverlauncher/release_commands.go")
require(release, ["managed-java-II-8-16-17-21-25"], "Managed Java II release gate")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestManagedJavaII", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Managed Java II gate: OK")

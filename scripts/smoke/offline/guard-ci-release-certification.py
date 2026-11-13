#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 13, 9):
    raise SystemExit("VERSION ниже 0.13.9")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


targets = json.loads(read("guard-ci/targets.json"))
if targets.get("schemaVersion") != "1.0" or targets.get("productVersion") != version:
    raise SystemExit("Несовпадение: «схема и версия целевых платформ CI защиты Guard»")
rows = targets.get("targets")
if not isinstance(rows, list) or {
    row.get("os") for row in rows if row.get("required")
} != {"linux", "windows", "macos"}:
    raise SystemExit("Целевые платформы Guard CI должны включать linux/windows/macos")
for row in rows:
    checks = set(row.get("requiredChecks", []))
    for required in {
        "guardIntegrationTest",
        "artifactHashesVerified",
        "authenticatedIpcV4",
        "runtimePolicyEnforced",
        "guardRelease0139",
    }:
        if required not in checks:
            raise SystemExit(f"{row.get('id')}: отсутствует {required}")

matrix = read("scripts/guard_ci/matrix.py")
require(
    matrix,
    [
        "guard-ci-result.json",
        "artifact filename collision across platforms",
        "vendorSigningProvenance",
        "not-certified-by-ci",
        "packageManifestBound",
        "repository=args.repository",
        "Guard CI matrix PASS",
    ],
    "матрица Guard CI",
)
stage = read("scripts/guard_ci/stage_release.py")
require(
    stage,
    [
        "Staged",
        "exact Guard CI-certified artifacts",
        "certified artifact mismatch",
        "duplicate staged source",
    ],
    "подготовка артефактов Guard",
)
release_go = read("cli/cmd/launcher/guard_ci_release.go")
require(
    release_go,
    [
        "GUARD_CI_TARGETS.json",
        "GUARD_CI_MATRIX.json",
        "GUARD_CI_CERTIFICATION.json",
        "guardCICertificationRequired",
        "verifyGuardCIArtifactsInDir",
        "all-required-cross-platform-guard-targets-pass-exact-commit-and-release-artifact-hashes",
    ],
    "сертификация Guard в CLI",
)
release_commands = read("cli/cmd/launcher/release_commands.go")
require(
    release_commands,
    [
        "--guard-ci-matrix",
        "verifyGuardCICertificationInBundle",
        "cross-platform-guard-ci-certification",
        "guardCICertified",
    ],
    "подключение проверки публикации релиза",
)
build_release = read("scripts/release/build-release.sh")
require(
    build_release,
    [
        "LAUNCHER_GUARD_CI_MATRIX_FILE",
        "LAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR",
        "stage_release.py",
        "--guard-ci-matrix",
        "cross-platform Guard CI certification",
    ],
    "подключение сборщика релизов",
)
ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        "guard-certification:",
        "guard-ci-linux-amd64",
        "guard-ci-windows-amd64",
        "guard-ci-macos-universal",
        "scripts/guard_ci/matrix.py aggregate",
        "launcher-guard-ci-matrix-",
    ],
    "матрица сертификации Guard в CI",
)
preflight = read("scripts/release/preflight.sh")
require(
    preflight,
    ["guard-ci-release-certification.py", "scripts/guard_ci/test_matrix.py"],
    "предварительная сертификация Guard",
)

subprocess.run(
    [
        sys.executable,
        str(root / "scripts/guard_ci/matrix.py"),
        "validate",
        "--targets",
        str(root / "guard-ci/targets.json"),
    ],
    cwd=root,
    check=True,
)
subprocess.run(
    [sys.executable, str(root / "scripts/guard_ci/test_matrix.py")],
    cwd=root,
    check=True,
)
print(
    "Launcher 0.13.9+: проверка кроссплатформенной матрицы Guard CI и сертификации релиза — OK"
)
print('cross-platform Guard CI matrix + release certification gate')

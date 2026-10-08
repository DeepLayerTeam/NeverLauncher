#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
ROLES = ("package", "launcher", "guard", "manifest", "allowlist")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TARGETS = {
    "guard-linux-amd64": {
        "package": f"neverlauncher-desktop-{VERSION}-linux-amd64.zip",
        "launcher": "neverlauncher-desktop-linux-amd64",
        "guard": "neverguard-linux-amd64",
        "manifest": "LINUX_PACKAGE_MANIFEST.json",
        "allowlist": "GUARD_RELEASE_ALLOWLIST_LINUX.json",
    },
    "guard-windows-amd64": {
        "package": f"neverlauncher-desktop-{VERSION}-windows-amd64.zip",
        "launcher": "neverlauncher-desktop-windows-amd64.exe",
        "guard": "neverguard-windows-amd64.exe",
        "manifest": "WINDOWS_PACKAGE_MANIFEST.json",
        "allowlist": "GUARD_RELEASE_ALLOWLIST_WINDOWS.json",
    },
    "guard-macos-universal": {
        "package": f"neverlauncher-desktop-{VERSION}-macos-universal.zip",
        "launcher": "neverlauncher-desktop-macos-universal",
        "guard": "neverguard-macos-universal",
        "manifest": "MACOS_PACKAGE_MANIFEST.json",
        "allowlist": "GUARD_RELEASE_ALLOWLIST_MACOS.json",
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(message: str) -> None:
    raise SystemExit(message)


def load_matrix(path: Path, expected_commit: str) -> dict[str, Any]:
    try:
        matrix = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"недопустимый Защита CI матрица: {exc}")
    if not isinstance(matrix, dict) or matrix.get("schemaVersion") != "1.0" or matrix.get("productVersion") != VERSION:
        fail(f"Защита CI матрица должен использовать schemaVersion=1.0 и productVersion={VERSION}")
    if matrix.get("status") != "passed" or matrix.get("errors") not in ([], None):
        fail("Защита CI матрица является не отказ с блокировкой пройден")
    commit = str(matrix.get("commit", "")).strip()
    run_id = str(matrix.get("runId", "")).strip()
    repository = str(matrix.get("repository", "")).strip()
    if not commit or not run_id or not repository:
        fail("Защита CI матрица является отсутствующий repository/commit/runId")
    if expected_commit and commit != expected_commit:
        fail(f"Защита CI матрица фиксация несоответствие: ожидаемый {expected_commit}, получил {commit}")
    rows = matrix.get("targets")
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_TARGETS):
        fail("Защита CI матрица должен contain точно three сертифицированный платформа цели")
    return matrix


def expected_artifacts(matrix: dict[str, Any]) -> dict[str, tuple[str, int, str, str]]:
    expected: dict[str, tuple[str, int, str, str]] = {}
    seen_targets: set[str] = set()
    for result in matrix["targets"]:
        if not isinstance(result, dict):
            fail("Защита CI матрица цель должен быть объект")
        target_id = str(result.get("targetId", "")).strip()
        if target_id not in EXPECTED_TARGETS or target_id in seen_targets:
            fail(f"unexpected или дубликат Защита CI цель: {target_id!r}")
        seen_targets.add(target_id)
        if result.get("schemaVersion") != "1.0" or result.get("productVersion") != VERSION:
            fail(f"Защита CI цель version/schema несоответствие: {target_id}")
        if result.get("status") != "passed" or result.get("exitCode") != 0:
            fail(f"Защита CI цель является не пройден: {target_id}")
        if str(result.get("commit", "")) != str(matrix.get("commit", "")) or str(result.get("runId", "")) != str(matrix.get("runId", "")):
            fail(f"Защита CI цель commit/run несоответствие: {target_id}")
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != set(ROLES):
            fail(f"недопустимый артефакт задать для {target_id}")
        canonical = EXPECTED_TARGETS[target_id]
        for role in ROLES:
            item = artifacts[role]
            if not isinstance(item, dict):
                fail(f"недопустимый {role} артефакт для {target_id}")
            name = str(item.get("name", ""))
            digest = str(item.get("sha256", "")).lower()
            size = item.get("size")
            if name != canonical[role]:
                fail(f"non-канонический сертифицированный артефакт имя для {target_id}/{role}: {name!r}")
            if not SHA256_RE.fullmatch(digest) or not isinstance(size, int) or size <= 0:
                fail(f"недопустимый сертифицированный артефакт hash/size для {target_id}/{role}")
            if name in expected:
                fail(f"дубликат сертифицированный артефакт имя: {name!r}")
            expected[name] = (digest, size, target_id, role)
    if seen_targets != set(EXPECTED_TARGETS):
        fail("Защита CI матрица делает не contain полный Linux/Windows/macOS цель задать")
    return expected


def copy_verified(src: Path, dst: Path, digest: str, size: int, context: str) -> None:
    if src.stat().st_size != size or sha256_file(src) != digest:
        fail(f"сертифицированный артефакт несоответствие для {context}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.", dir=str(dst.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copyfile(src, tmp)
        if tmp.stat().st_size != size or sha256_file(tmp) != digest:
            fail(f"подготовленный артефакт проверка ошибка для {context}")
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Подготавливать точный Защита CI-сертифицированный артефакты в комплект релиза")
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-commit", default="")
    args = parser.parse_args()
    matrix = load_matrix(args.matrix, args.expected_commit.strip())
    expected = expected_artifacts(matrix)
    found: dict[str, Path] = {}
    for path in args.artifacts_root.rglob("*"):
        if not path.is_file() or path.name not in expected:
            continue
        if path.name in found:
            fail(f"дубликат подготовленный исходник для {path.name}: {found[path.name]} и {path}")
        found[path.name] = path
    missing = sorted(set(expected) - set(found))
    if missing:
        fail("отсутствующий сертифицированный платформа артефакты: " + ", ".join(missing))
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(expected):
        digest, size, target_id, role = expected[name]
        copy_verified(found[name], args.out / name, digest, size, f"{target_id}/{role}/{name}")
    print(f"Подготовленный {len(expected)} точный Защита CI-сертифицированный артефакты в {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

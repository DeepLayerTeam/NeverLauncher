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
        fail(f"invalid Guard CI matrix: {exc}")
    if not isinstance(matrix, dict) or matrix.get("schemaVersion") != "1.0" or matrix.get("productVersion") != VERSION:
        fail(f"Guard CI matrix must use schemaVersion=1.0 and productVersion={VERSION}")
    if matrix.get("status") != "passed" or matrix.get("errors") not in ([], None):
        fail("Guard CI matrix is not fail-closed passed")
    commit = str(matrix.get("commit", "")).strip()
    run_id = str(matrix.get("runId", "")).strip()
    repository = str(matrix.get("repository", "")).strip()
    if not commit or not run_id or not repository:
        fail("Guard CI matrix is missing repository/commit/runId")
    if expected_commit and commit != expected_commit:
        fail(f"Guard CI matrix commit mismatch: expected {expected_commit}, got {commit}")
    rows = matrix.get("targets")
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_TARGETS):
        fail("Guard CI matrix must contain exactly three certified platform targets")
    return matrix


def expected_artifacts(matrix: dict[str, Any]) -> dict[str, tuple[str, int, str, str]]:
    expected: dict[str, tuple[str, int, str, str]] = {}
    seen_targets: set[str] = set()
    for result in matrix["targets"]:
        if not isinstance(result, dict):
            fail("Guard CI matrix target must be an object")
        target_id = str(result.get("targetId", "")).strip()
        if target_id not in EXPECTED_TARGETS or target_id in seen_targets:
            fail(f"unexpected or duplicate Guard CI target: {target_id!r}")
        seen_targets.add(target_id)
        if result.get("schemaVersion") != "1.0" or result.get("productVersion") != VERSION:
            fail(f"Guard CI target version/schema mismatch: {target_id}")
        if result.get("status") != "passed" or result.get("exitCode") != 0:
            fail(f"Guard CI target is not passed: {target_id}")
        if str(result.get("commit", "")) != str(matrix.get("commit", "")) or str(result.get("runId", "")) != str(matrix.get("runId", "")):
            fail(f"Guard CI target commit/run mismatch: {target_id}")
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != set(ROLES):
            fail(f"invalid artifact set for {target_id}")
        canonical = EXPECTED_TARGETS[target_id]
        for role in ROLES:
            item = artifacts[role]
            if not isinstance(item, dict):
                fail(f"invalid {role} artifact for {target_id}")
            name = str(item.get("name", ""))
            digest = str(item.get("sha256", "")).lower()
            size = item.get("size")
            if name != canonical[role]:
                fail(f"non-canonical certified artifact name for {target_id}/{role}: {name!r}")
            if not SHA256_RE.fullmatch(digest) or not isinstance(size, int) or size <= 0:
                fail(f"invalid certified artifact hash/size for {target_id}/{role}")
            if name in expected:
                fail(f"duplicate certified artifact name: {name!r}")
            expected[name] = (digest, size, target_id, role)
    if seen_targets != set(EXPECTED_TARGETS):
        fail("Guard CI matrix does not contain the complete Linux/Windows/macOS target set")
    return expected


def copy_verified(src: Path, dst: Path, digest: str, size: int, context: str) -> None:
    if src.stat().st_size != size or sha256_file(src) != digest:
        fail(f"certified artifact mismatch for {context}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.", dir=str(dst.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copyfile(src, tmp)
        if tmp.stat().st_size != size or sha256_file(tmp) != digest:
            fail(f"staged artifact verification failed for {context}")
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage exact Guard CI-certified artifacts into a release bundle")
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
            fail(f"duplicate staged source for {path.name}: {found[path.name]} and {path}")
        found[path.name] = path
    missing = sorted(set(expected) - set(found))
    if missing:
        fail("missing certified platform artifacts: " + ", ".join(missing))
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(expected):
        digest, size, target_id, role = expected[name]
        copy_verified(found[name], args.out / name, digest, size, f"{target_id}/{role}/{name}")
    print(f"Staged {len(expected)} exact Guard CI-certified artifacts into {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

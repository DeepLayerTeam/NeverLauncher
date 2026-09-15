#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import zipfile
from pathlib import Path

TOP_FILES = {
    ".gitignore", ".env.example", "VERSION", "README.md", "CHANGELOG.md",
    "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "LICENSE",
    "NOTICE", "settings.gradle.kts",
}
TOP_DIRS = {
    ".github", "schemas", "plugins", "scripts", "runtime", "e2e", "tests",
    "cli", "apps", "services", "deploy",
}
EXCLUDED_PARTS = {".git", "node_modules", "target", "dist", ".neverlauncher", "build", ".gradle"}
SECRET_NAMES = {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
SECRET_SUFFIXES = {".key", ".p12", ".pfx", ".jks", ".keystore"}
SECRET_DIRS = {"secret", "secrets", "credential", "credentials"}


def safe_rel(rel: str) -> bool:
    rel = rel.replace("\\", "/").strip("/")
    if not rel or rel.startswith("../") or "/../" in rel:
        return False
    p = Path(rel)
    parts = set(p.parts)
    lower_parts = {part.lower() for part in p.parts}
    if parts & EXCLUDED_PARTS or lower_parts & SECRET_DIRS:
        return False
    name = p.name.lower()
    if name in SECRET_NAMES and name != ".env.example":
        return False
    if any(name.endswith(s) for s in SECRET_SUFFIXES):
        return False
    if name.endswith(".pem") and not name.endswith(".example.pem"):
        return False
    first = p.parts[0]
    return rel in TOP_FILES or first in TOP_DIRS


def tracked_files(root: Path) -> list[str]:
    if (root / ".git").exists():
        try:
            raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"], stderr=subprocess.STDOUT)
            items = [x.decode("utf-8") for x in raw.split(b"\0") if x]
            return sorted(rel for rel in items if safe_rel(rel) and (root / rel).is_file() and not (root / rel).is_symlink())
        except Exception:
            pass
    items: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if safe_rel(rel):
            items.append(rel)
    return sorted(items)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("output")
    ap.add_argument("--list-file")
    ns = ap.parse_args()
    root = Path(ns.root).resolve()
    out = Path(ns.output).resolve()
    files = tracked_files(root)
    if not files:
        raise SystemExit("source allowlist пуст")
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel in files:
            zf.write(root / rel, rel)
    if ns.list_file:
        Path(ns.list_file).write_text("\n".join(files) + "\n", encoding="utf-8")
    print(f"source-package: {len(files)} allowlisted files -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

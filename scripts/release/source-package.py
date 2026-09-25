#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
    "cli", "apps", "services", "deploy", "compatibility", "device-trust",
    "guard-ci", "serverbridge",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", "target", "dist", ".neverlauncher", "build", ".gradle",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".vite", ".npm",
    ".idea", ".vscode", "coverage", "out",
}
EXCLUDED_NAMES = {".DS_Store", "Thumbs.db", ".eslintcache", ".coverage", "coverage.out"}
EXCLUDED_SUFFIXES = {
    ".pyc", ".pyo", ".log", ".tmp", ".swp", ".swo", ".bak", ".test", ".prof",
    ".coverprofile", ".tsbuildinfo", ".pid", ".pid.lock", ".sock",
}
EXCLUDED_PREFIXES = {
    "e2e/runtime/", "e2e/runtime-ci/", "e2e/reports/", "e2e/compatibility-result/",
    "e2e/device-trust-runtime/", "e2e/device-trust-result/",
    "deploy/production/certs/", "deploy/production/acme/",
}
EXCLUDED_PATHS = {
    "cli/nl", "cli/nl.exe", "services/api/neverlauncher-api", "services/api/neverlauncher-api.exe",
}
SECRET_NAMES = {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
SECRET_SUFFIXES = {".key", ".p12", ".pfx", ".jks", ".keystore"}
SECRET_DIRS = {"secret", "secrets", "credential", "credentials"}


def safe_rel(rel: str) -> bool:
    rel = rel.replace("\\", "/").strip("/")
    if not rel or rel.startswith("../") or "/../" in rel:
        return False
    p = Path(rel)
    lower_parts = {part.lower() for part in p.parts}
    if rel in EXCLUDED_PATHS or any(rel.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return False
    for part in p.parts:
        if part not in EXCLUDED_PARTS:
            continue
        # scripts/build contains the canonical ServerBridge production build entrypoint.
        # Other build directories remain generated output and must stay excluded.
        if part == "build" and len(p.parts) >= 2 and p.parts[0] == "scripts" and p.parts[1] == "build":
            continue
        return False
    if lower_parts & SECRET_DIRS:
        return False
    name = p.name.lower()
    if p.name in EXCLUDED_NAMES or name in {item.lower() for item in EXCLUDED_NAMES}:
        return False
    if any(name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES) or name.endswith("~"):
        return False
    if name.startswith("coverage") and name.endswith(".out"):
        return False
    if name in SECRET_NAMES and name != ".env.example":
        return False
    if name.startswith(".env.") and name != ".env.example":
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

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION_FILE = ROOT / "VERSION"
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


class VersionError(RuntimeError):
    pass


def read_version() -> str:
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not SEMVER_RE.fullmatch(version):
        raise VersionError(f"VERSION содержит некорректную SemVer-версию: {version!r}")
    return version


def render_json(path: Path, version: str) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = version
    if path.name == "package-lock.json":
        packages = data.get("packages")
        if isinstance(packages, dict) and isinstance(packages.get(""), dict):
            packages[""]["version"] = version
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"



def render_product_version_json(path: Path, version: str) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "productVersion" not in data:
        raise VersionError(f"{path.relative_to(ROOT)}: не найден productVersion")
    data["productVersion"] = version
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"

def replace_package_version(text: str, version: str, path: Path) -> str:
    updated, count = re.subn(r'(?m)^(version\s*=\s*)"[^"]+"\s*$', rf'\1"{version}"', text, count=1)
    if count != 1:
        raise VersionError(f"{path.relative_to(ROOT)}: не найден package version")
    return updated


def replace_env_image_tag(text: str, version: str, path: Path) -> str:
    updated, count = re.subn(r"(?m)^NEVERLAUNCHER_IMAGE_TAG=.*$", f"NEVERLAUNCHER_IMAGE_TAG={version}", text, count=1)
    if count != 1:
        raise VersionError(f"{path.relative_to(ROOT)}: не найден NEVERLAUNCHER_IMAGE_TAG")
    return updated


def desired_files(version: str) -> dict[Path, str]:
    result: dict[Path, str] = {}
    for rel in (
        "apps/admin/package.json",
        "apps/admin/package-lock.json",
        "apps/desktop/package.json",
        "apps/desktop/package-lock.json",
        "apps/desktop/src-tauri/tauri.conf.json",
    ):
        path = ROOT / rel
        result[path] = render_json(path, version)

    for rel in ("runtime/neverruntime/Cargo.toml", "apps/desktop/src-tauri/Cargo.toml"):
        path = ROOT / rel
        result[path] = replace_package_version(path.read_text(encoding="utf-8"), version, path)

    device_trust_targets = ROOT / "device-trust/targets.json"
    result[device_trust_targets] = render_product_version_json(device_trust_targets, version)

    guard_ci_targets = ROOT / "guard-ci/targets.json"
    result[guard_ci_targets] = render_product_version_json(guard_ci_targets, version)

    for rel in ("deploy/production/env.production.example", "cli/cmd/neverlauncher/templates/production/env.production.example"):
        path = ROOT / rel
        result[path] = replace_env_image_tag(path.read_text(encoding="utf-8"), version, path)
    return result


def sync(version: str, *, check_only: bool) -> list[str]:
    changed: list[str] = []
    for path, desired in desired_files(version).items():
        current = path.read_text(encoding="utf-8")
        if current == desired:
            continue
        rel = path.relative_to(ROOT).as_posix()
        changed.append(rel)
        if not check_only:
            path.write_text(desired, encoding="utf-8")
    return changed


def command_check() -> int:
    version = read_version()
    drift = sync(version, check_only=True)
    schema = (ROOT / "schemas/openapi.yaml").read_text(encoding="utf-8")
    if f"NeverLauncher {version}." not in schema:
        drift.append("schemas/openapi.yaml")
    if drift:
        print(f"Version metadata drift for VERSION={version}:", file=sys.stderr)
        for rel in drift:
            print(f" - {rel}", file=sys.stderr)
        print("Run: python3 scripts/version/manage.py sync", file=sys.stderr)
        return 1
    print(f"NeverLauncher version metadata OK: {version} (source: VERSION)")
    return 0


def command_sync() -> int:
    version = read_version()
    changed = sync(version, check_only=False)
    subprocess.run([sys.executable, str(ROOT / "scripts/contracts/generate_openapi.py")], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    if changed:
        print(f"Synced VERSION={version} into {len(changed)} required metadata files (+ generated OpenAPI):")
        for rel in changed:
            print(f" - {rel}")
    else:
        print(f"Version metadata already synchronized: {version}; OpenAPI regenerated")
    return 0


def command_set(value: str) -> int:
    value = value.strip()
    if not SEMVER_RE.fullmatch(value):
        raise VersionError(f"invalid SemVer: {value!r}")
    VERSION_FILE.write_text(value + "\n", encoding="utf-8")
    sync(value, check_only=False)
    subprocess.run([sys.executable, str(ROOT / "scripts/contracts/generate_openapi.py")], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    print(f"NeverLauncher version set to {value}; VERSION is the canonical source")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NeverLauncher canonical version manager")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("get")
    sub.add_parser("check")
    sub.add_parser("sync")
    set_parser = sub.add_parser("set")
    set_parser.add_argument("version")
    args = parser.parse_args()
    try:
        if args.command == "get":
            print(read_version())
            return 0
        if args.command == "check":
            return command_check()
        if args.command == "sync":
            return command_sync()
        return command_set(args.version)
    except (OSError, ValueError, json.JSONDecodeError, VersionError) as exc:
        print(f"version-manager: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

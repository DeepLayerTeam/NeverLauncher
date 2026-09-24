#!/usr/bin/env python3
"""Merge platform NeverGuard release-policy fragments into one production policy.

The command is intentionally fail-closed: all three platforms must be present for
0.14.x, hashes must be canonical SHA-256, Windows must require Authenticode, and
macOS must originate from the Developer ID + notarization production path.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLATFORMS = {
    "windows": ("authenticode", True),
    "linux": ("integrity-only", False),
    "macos": ("developer-id-notarized", False),
}


def die(message: str) -> "NoReturn":
    raise SystemExit(message)


def load_fragment(path: Path, expected_platform: str) -> dict:
    try:
        root = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"{path}: invalid JSON: {exc}")
    if not isinstance(root, dict) or root.get("schemaVersion") != "2.0":
        die(f"{path}: schemaVersion must be 2.0")
    releases = root.get("releases")
    release = releases.get(VERSION) if isinstance(releases, dict) else None
    if not isinstance(release, dict) or release.get("protocolVersion") != 4:
        die(f"{path}: release {VERSION} with protocolVersion=4 is required")
    platforms = release.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != {expected_platform}:
        die(f"{path}: fragment must contain only platform {expected_platform}")
    policy = platforms[expected_platform]
    if not isinstance(policy, dict):
        die(f"{path}: malformed {expected_platform} policy")
    expected_signing, auth_required = PLATFORMS[expected_platform]
    if policy.get("signingMode") != expected_signing:
        die(f"{path}: production {expected_platform} signingMode must be {expected_signing}")
    artifacts = policy.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 32:
        die(f"{path}: artifacts must contain 1..32 exact pairs")
    seen: set[tuple[str, str]] = set()
    normalized = []
    for row in artifacts:
        if not isinstance(row, dict):
            die(f"{path}: artifact pair must be an object")
        guard = str(row.get("guardSha256", "")).lower()
        launcher = str(row.get("launcherSha256", "")).lower()
        if not SHA256_RE.fullmatch(guard) or not SHA256_RE.fullmatch(launcher):
            die(f"{path}: artifact pair contains malformed SHA-256")
        pair = (guard, launcher)
        if pair in seen:
            die(f"{path}: duplicate artifact pair")
        seen.add(pair)
        out = {"guardSha256": guard, "launcherSha256": launcher}
        if expected_platform == "windows":
            if row.get("requireAuthenticode") is not True:
                die(f"{path}: Windows production pair must require Authenticode")
            out["requireAuthenticode"] = True
        elif row.get("requireAuthenticode") not in (None, False):
            die(f"{path}: requireAuthenticode is invalid for {expected_platform}")
        normalized.append(out)
    return {"signingMode": expected_signing, "artifacts": normalized}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--macos", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    merged = {
        "schemaVersion": "2.0",
        "releases": {
            VERSION: {
                "protocolVersion": 4,
                "platforms": {
                    "windows": load_fragment(args.windows, "windows"),
                    "linux": load_fragment(args.linux, "linux"),
                    "macos": load_fragment(args.macos, "macos"),
                },
            }
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

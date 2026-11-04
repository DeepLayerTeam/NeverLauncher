#!/usr/bin/env python3
"""Bind independently approved live GA targets to the EXACT six shipped packages.

Run after the protected Windows/Linux/macOS signed artifacts have been imported,
but before release manifest generation and Ed25519 signing. No fallback names.
"""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from official_minecraft_0270 import strict_json, GateError, TARGETS, require, SHA256

PACKAGES = {
    "windows-amd64": "launcher-desktop-0.27.0-windows-x64.zip",
    "windows-arm64": "launcher-desktop-0.27.0-windows-arm64.zip",
    "linux-amd64": "launcher-linux-x64-0.27.0.tar.gz",
    "linux-arm64": "launcher-linux-arm64-0.27.0.tar.gz",
    "darwin-amd64": "launcher-desktop-0.27.0-macos-x64.zip",
    "darwin-arm64": "launcher-desktop-0.27.0-macos-arm64.zip",
}


def verify_shipped(bundle: Path, receipt_path: Path) -> dict:
    require(
        bundle.is_dir()
        and not bundle.is_symlink()
        and not receipt_path.is_symlink()
        and receipt_path.is_file()
        and receipt_path.stat().st_size <= 32 * 1024,
        "invalid GA receipt/bundle path",
    )
    receipt = strict_json(receipt_path.read_bytes())
    require(
        receipt.get("schemaVersion") == "launcher.official-minecraft.ga-receipt.v1"
        and receipt.get("productVersion") == "0.27.0"
        and receipt.get("status") == "passed",
        "incomplete GA receipt",
    )
    refs = receipt.get("targets")
    require(
        type(refs) is list and len(refs) == len(PACKAGES),
        "expected six certified package digests",
    )
    checked = set()
    digests = {}
    for reference in refs:
        require(type(reference) is dict, "invalid signed GA target")
        target = reference.get("target")
        require(
            target in PACKAGES
            and target not in checked
            and reference.get("status") == "passed",
            "invalid/duplicate GA target",
        )
        digest = reference.get("signedArtifactSha256")
        require(
            isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
            "missing approved installer digest",
        )
        artifact = bundle / PACKAGES[target]
        require(
            not artifact.is_symlink()
            and artifact.is_file()
            and artifact.stat().st_size > 0,
            f"signed deliverable missing: {target}",
        )
        h = hashlib.sha256()
        with artifact.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(block)
        require(
            h.hexdigest() == digest,
            f"{target}: shipping package differs from independently certified executable",
        )
        checked.add(target)
        digests[target] = digest
    require(checked == PACKAGES.keys(), "missing certified shipping target")
    return digests


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--receipt", required=True, type=Path)
    args = ap.parse_args()
    try:
        digests = verify_shipped(args.bundle, args.receipt)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"0.27.0 artifact binding failed: {exc}", file=sys.stderr)
        return 2
    print(f"0.27.0 GA: {len(digests)} exact native production package hashes verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Build, Ed25519-sign and VERIFY runnable Java Extensions example packages.

The output is a verified signed *example*, not a platform parity certificate.
Production issuer trust must be configured separately on the installed backend.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ("java-host", "gravit-compat")


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def package(cli: Path, private_key: Path, public_key: Path, output: Path) -> dict:
    cli, private_key, public_key = [
        p.resolve(strict=True) for p in (cli, private_key, public_key)
    ]
    if not cli.is_file() or not private_key.is_file() or not public_key.is_file():
        raise ValueError("expected real CLI and key files")
    if output.is_symlink() or (output.exists() and any(output.iterdir())):
        raise ValueError("output must be an empty regular directory")
    output.mkdir(parents=True, exist_ok=True)
    version = (ROOT / "VERSION").read_text().strip()
    if version != "0.31.0":
        raise ValueError("package release must match VERSION=0.31.0")
    records = []
    for name in EXAMPLES:
        # This script invokes the existing working Java compiler and signer.
        run(["sh", f"examples/extensions/{name}/build.sh"])
        package_path = output / f"{name}-{version}.nlext"
        run(
            [
                str(cli),
                "extension",
                "pack",
                f"examples/extensions/{name}/build/package",
                "--output",
                str(package_path),
                "--private-key",
                str(private_key),
            ]
        )
        run(
            [
                str(cli),
                "extension",
                "verify",
                str(package_path),
                "--public-key",
                str(public_key),
            ]
        )
        records.append(
            {
                "name": name,
                "filename": package_path.name,
                "sha256": hashlib.sha256(package_path.read_bytes()).hexdigest(),
                "verified": True,
                "productionCertified": False,
            }
        )
    manifest = {
        "schemaVersion": "1.0",
        "productVersion": version,
        "kind": "signed-java-examples",
        "note": "These are integration test examples, not certified production/Gravit parity packages.",
        "packages": records,
    }
    (output / "index.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf8"
    )
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = package(args.cli, args.private_key, args.public_key, args.output)
        for record in manifest["packages"]:
            print(record["filename"], record["sha256"])
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        parser.exit(1, f"package verification failed: {e}\n")


if __name__ == "__main__":
    main()

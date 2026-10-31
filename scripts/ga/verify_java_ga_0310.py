#!/usr/bin/env python3
"""Fail-closed, independently Ed25519-authorized Launcher 0.31.0 GA gate.

The operator signs the *exact* cross-platform review JSON emitted by CI, not
an untrusted user-supplied success flag. This is a release approval gate, not
proof of full binary compatibility with every upstream Gravit JAR.
"""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/certification"))
from review_integration_0310 import review, REVISION


def verify(evidence: Path, revision: str, public_key: Path, signature: Path) -> dict:
    if not REVISION.fullmatch(revision):
        raise ValueError("revision must be a full lowercase Git SHA")
    if (ROOT / "VERSION").read_text(encoding="utf8").strip() != "0.31.0":
        raise ValueError("GA approval only applies to VERSION 0.31.0")
    if not evidence.is_dir() or evidence.is_symlink():
        raise ValueError("invalid evidence directory")
    for p in (public_key, signature):
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 65536:
            raise ValueError(f"absent/invalid release approval input: {p}")
        if p.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError(
                "approval trust anchors and signatures must be outside the source tree"
            )
    reports = sorted(evidence.rglob("integration-0310.json"))
    summary = review(reports, revision)
    payload = (json.dumps(summary, indent=2) + "\n").encode("utf8")
    with tempfile.TemporaryDirectory(prefix="nl-ga-approval-") as work:
        data = Path(work) / "review.json"
        data.write_bytes(payload)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key.resolve()),
                "-rawin",
                "-in",
                str(data),
                "-sigfile",
                str(signature.resolve()),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise ValueError("release approval signature invalid")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.evidence, args.revision, args.public_key, args.signature)
    except (ValueError, OSError, subprocess.CalledProcessError, TypeError) as e:
        parser.exit(1, f"Launcher GA BLOCKED: {e}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

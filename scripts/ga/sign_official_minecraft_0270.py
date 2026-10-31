#!/usr/bin/env python3
"""Sign independently reviewed live GA evidence using a protected operator key.

Never create or publish a private key here. This refuses to sign missing, stale,
self-contradictory or synthetic evidence, using the same semantic gate as CI.
"""

from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from official_minecraft_0270 import (
    DOMAIN,
    GateError,
    strict_json,
    TARGETS,
    GITSHA,
    verify_target,
    checked_time,
)
from datetime import datetime, timezone


def sign_attestation(
    folder: Path, expected_public: str, seed_hex: str, commit: str
) -> None:
    if not GITSHA.fullmatch(commit):
        raise GateError("exact source commit required")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", seed_hex):
        raise GateError("protected Ed25519 seed is missing/invalid")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_public):
        raise GateError("pinned operator public key invalid")
    if (
        folder.is_symlink()
        or not folder.is_dir()
        or (folder / "attestation.json").is_symlink()
    ):
        raise GateError("unsafe evidence directory")
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    actual_public = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    if actual_public != expected_public.lower():
        raise GateError(
            "operator signing key differs from protected verification anchor"
        )
    attestation = folder / "attestation.json"
    raw = attestation.read_bytes()
    if len(raw) > 64 * 1024:
        raise GateError("oversized attestation")
    data = strict_json(raw)
    if data.get("commit") != commit or data.get("productVersion") != "0.27.0":
        raise GateError("attestation does not describe requested exact source")
    if data.get("target") not in {
        f"{p}-{a}" for p, a in TARGETS
    } or folder.name != data.get("target"):
        raise GateError("attestation target mismatches its directory")
    if (folder / "attestation.sig").exists() or (
        folder / "attestation.sig"
    ).is_symlink():
        raise GateError("signature already exists; do not overwrite operator approvals")
    signature = private.sign(DOMAIN + raw).hex().encode("ascii") + b"\n"
    # Create-only and user-only permissions. A crash leaves no successful release
    # receipt: caller must inspect/remove an incomplete signature explicitly.
    fd = os.open(
        folder / "attestation.sig", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(signature)
            stream.flush()
            os.fsync(stream.fileno())
        platform, arch = data["target"].split("-")
        verify_target(
            folder.parent,
            platform,
            arch,
            private.public_key(),
            commit,
            datetime.now(timezone.utc),
        )
    except BaseException:
        (folder / "attestation.sig").unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument(
        "--public-key",
        required=True,
        help="public signing anchor pinned outside repository",
    )
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    seed = os.environ.get("LAUNCHER_OFFICIAL_GA_ED25519_SEED", "")
    try:
        sign_attestation(args.target_dir, args.public_key, seed, args.commit)
    except (GateError, OSError, ValueError) as exc:
        print(f"GA operator signing refused: {exc}", file=sys.stderr)
        return 2
    print("Verified and signed exact live evidence for", args.target_dir.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())

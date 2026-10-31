#!/usr/bin/env python3
"""Offline root signing for cross-component key delegation.

The root seed must come from a protected release environment. It is never
shipped to clients or included in a branded bundle.
"""

import argparse
import base64
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PREFIX = b"Launcher-Trust-Policy-v1\n"


def sign_policy(
    payload_path: Path, output_path: Path, seed_hex: str, expected_root: str
) -> None:
    payload = payload_path.read_bytes()
    if len(payload) > 96 * 1024:
        raise ValueError("policy payload is too large")
    value = json.loads(payload)
    if (
        value.get("schemaVersion") != "1.0"
        or value.get("domain") != "launcher.trust.v1"
        or type(value.get("epoch")) is not int
        or value["epoch"] < 1
    ):
        raise ValueError("trust policy version/domain/epoch invalid")
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    actual = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    if actual != expected_root.strip().lower():
        raise ValueError("root signing key does not match provisioned client anchor")
    sig = private.sign(PREFIX + payload)
    envelope = {
        "schemaVersion": "1.0",
        "payload": base64.b64encode(payload).decode(),
        "rootSignature": sig.hex(),
    }
    output_path.write_text(
        json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--root-key-hex",
        required=True,
        help="already provisioned root PUBLIC key, never from downloaded metadata",
    )
    args = parser.parse_args()
    seed = os.environ.get("NEVERLAUNCHER_TRUST_ROOT_ED25519_SEED", "")
    if not seed:
        raise SystemExit("offline NEVERLAUNCHER_TRUST_ROOT_ED25519_SEED required")
    sign_policy(args.payload, args.output, seed, args.root_key_hex)


if __name__ == "__main__":
    main()

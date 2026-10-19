#!/usr/bin/env python3
"""Build the authenticated 0.23.10 component protocol set and detached signature.

The release signing seed is never written to disk. Public verification key is
pinned separately into the updater binary during trusted build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def required(version: str) -> bool:
    major, minor, patch = (int(s) for s in version.split(".")[:3])
    return (major, minor, patch) >= (0, 23, 10)


def signed_set(manifest: dict, *, development: bool = False) -> tuple[bytes, bytes | None]:
    if not required(manifest["productVersion"]):
        return (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode(), None
    platform = manifest["platform"]
    components = {x["component"] for x in manifest["components"]}
    if components != ({"desktop", "guard", "runtime", "sensor"} if platform == "windows" else {"desktop", "guard", "runtime"}):
        raise ValueError("unexpected component role set")
    helpers = [x for x in manifest.get("supportFiles", []) if x["component"] == "updater"]
    if len(helpers) != 1 or not helpers[0]["executable"]:
        raise ValueError("component update helper missing")
    rows = [
        {"component": "desktop", "provides": {"guard-ipc": 4}, "requires": [
            {"component": "guard", "protocol": "guard-ipc", "minimum": 4},
            {"component": "runtime", "protocol": "guard-ipc", "minimum": 4},
            {"component": "updater", "protocol": "component-update", "minimum": 2},
        ]},
        {"component": "guard", "provides": {"guard-ipc": 4}, "requires": [
            {"component": "runtime", "protocol": "guard-ipc", "minimum": 4},
        ]},
        {"component": "runtime", "provides": {"guard-ipc": 4}, "requires": [
            {"component": "guard", "protocol": "guard-ipc", "minimum": 4},
        ]},
        {"component": "updater", "provides": {"component-update": 2}, "requires": [
            {"component": "desktop", "protocol": "guard-ipc", "minimum": 4},
        ]},
    ]
    if platform == "windows":
        rows[1]["requires"].append({"component": "sensor", "protocol": "sensor-ipc", "minimum": 3})
        rows.append({"component": "sensor", "provides": {"sensor-ipc": 3}})
    # Preserve 1.0 for the upgrade from the 0.23.9 external updater,
    # which is already pinned by package SHA-256. New updaters enforce
    # the signed component-set sidecar and the protocol matrix.
    manifest["schemaVersion"] = "1.0"
    manifest["componentSet"] = {"schemaVersion": "1.0", "protocols": rows}
    raw = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    seed = os.environ.get("NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED", "").strip()
    if not seed:
        if development:
            return raw, None
        raise RuntimeError("production component update requires NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed_bytes = bytes.fromhex(seed)
    if len(seed_bytes) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes in hexadecimal")
    key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    expected_pub = os.environ.get("NEVERLAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY", "").strip().lower()
    actual_pub = key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    if not expected_pub or expected_pub != actual_pub:
        raise RuntimeError("component-set signing key does not match embedded public trust root")
    signature = key.sign(raw)
    envelope = {"schemaVersion": "1.0", "algorithm": "ed25519", "manifestSha256": hashlib.sha256(raw).hexdigest(), "signature": signature.hex()}
    signed = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()
    return raw, signed


def sign_file(manifest_path: Path, *, development: bool = False) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw, envelope = signed_set(manifest, development=development)
    manifest_path.write_bytes(raw)
    sig_path = manifest_path.with_name("COMPONENT_SET_SIGNATURE.json")
    if envelope is not None:
        sig_path.write_bytes(envelope)
    else:
        sig_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--development", action="store_true")
    args = parser.parse_args()
    sign_file(args.manifest, development=args.development)


if __name__ == "__main__":
    main()

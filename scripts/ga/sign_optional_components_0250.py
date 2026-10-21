#!/usr/bin/env python3
"""Sign an independently produced 0.25.0 GA attestation in an approved CI.

This tool never generates 'passed' check results, test receipts, installers or
release signing keys. It validates all evidence before issuing the signature.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from release_gate import (COMPONENT_GA_DOMAIN, COMPONENT_GA_SCHEMA, COMPONENT_GA_CHECKS,
                          COMMON_CHECKS, load_attested_file, check_report,
                          strict_json, verify_target)

REQUIRED_OBJECTS = {"installer", "osSignature", "cleanMachine", "certification",
                    "benchmark", "components", "nativeRun", "minecraftRun", "guardRun", "bridgeRun"}


def sign_existing_attestation(folder: Path, key_path: Path, *, trusted_key_hex: str, commit: str) -> None:
    if folder.is_symlink() or key_path.is_symlink():
        raise ValueError("symlinked signing input is prohibited")
    # Ensure the trust root was approved separately from this signing run.
    if not re.fullmatch(r"[a-fA-F0-9]{64}", trusted_key_hex):
        raise ValueError("a pinned trusted 32-byte Ed25519 public key is mandatory")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("a full, exact source Git commit is mandatory")
    if os.name != 'nt' and key_path.stat().st_mode & 0o077:
        raise ValueError("signing private key must not be readable by group/others")
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("expected PEM-encoded Ed25519 private key")
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if public.lower() != trusted_key_hex.lower():
        raise ValueError("signing key differs from approved independent GA trust anchor")
    attestation_file = folder / 'attestation.json'
    if attestation_file.is_symlink() or not attestation_file.is_file():
        raise ValueError("ordinary attestation.json required")
    raw = attestation_file.read_bytes()
    if len(raw) > 1024*1024:
        raise ValueError("attestation too large")
    doc = strict_json(raw)
    if doc.get('schemaVersion') != COMPONENT_GA_SCHEMA or doc.get('productVersion') != '0.25.0' or doc.get('commit') != commit:
        raise ValueError("unsupported GA attestation or source mismatch")
    if doc.get('status') != 'passed' or doc.get('gitTreeClean') is not True:
        raise ValueError("incomplete GA source")
    platform, arch = doc.get('platform'), doc.get('architecture')
    if folder.name != f'{platform}-{arch}':
        raise ValueError("platform/architecture not bound to directory")
    objects = doc.get('objects')
    if not isinstance(objects, dict) or set(objects) != REQUIRED_OBJECTS:
        raise ValueError("missing or extra evidence objects")
    for name, value in objects.items():
        if not isinstance(value, dict):
            raise ValueError("invalid evidence object")
        content = load_attested_file(folder, value.get('file'), value.get('sha256'), binary=name=='installer')
        if name != 'installer':
            check_report(content, commit=commit, version='0.25.0', subject=name, target=folder.name)
    # The full verifier performs cross-object digest, installer/OS-signature,
    # platform and mandatory-check comparisons before this receipt is accepted.
    sig_path = folder / 'attestation.sig'
    if sig_path.exists() or sig_path.is_symlink():
        raise ValueError("refusing to overwrite a previously signed attestation")
    sig_path.write_text(private.sign(COMPONENT_GA_DOMAIN + raw).hex() + '\n', encoding='ascii')
    try:
        verify_target(folder, private.public_key(), commit, '0.25.0')
    except Exception:
        sig_path.unlink()
        raise


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--folder', type=Path, required=True)
    p.add_argument('--private-key', type=Path, required=True)
    p.add_argument('--trusted-ga-public-key', required=True)
    p.add_argument('--commit', required=True)
    args = p.parse_args()
    try:
        sign_existing_attestation(args.folder, args.private_key,
                                 trusted_key_hex=args.trusted_ga_public_key, commit=args.commit)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f'GA attestation not signed: {exc}', file=sys.stderr)
        return 1
    print('Signed and independently verified GA evidence for', args.folder.name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline independent-review helper: sign EXACT final Guard evidence tree.

Run on the independent reviewer's machine only, with an external Ed25519 PEM
private key, after inspecting actual native, Minecraft and pilot outputs. This
command never changes Guard enforcement or declares GA; the GA gate verifies
all evidence and separately checks the pinned reviewer's public key.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guard_ga_0510 import DOMAIN, SCHEMA, VERSION, evidence_inventory, require, IDENTITY, COMMIT


def sign(root: Path, key_path: Path, reviewer: str, publisher: str, commit: str,
         output: Path, signature: Path) -> dict:
    require(bool(IDENTITY.fullmatch(reviewer)) and bool(IDENTITY.fullmatch(publisher))
            and reviewer != publisher, 'independent reviewer and different publisher required')
    require(bool(COMMIT.fullmatch(commit)), 'exact source commit required')
    require(key_path.is_file() and not key_path.is_symlink(), 'independent PEM key missing')
    if os.name != 'nt':
        require(key_path.stat().st_mode & 0o077 == 0, 'reviewer private key permissions must be 0600')
    require(not output.resolve().is_relative_to(root.resolve()) and
            not signature.resolve().is_relative_to(root.resolve()),
            'approval and detached signature must be outside the evidence tree')
    private = load_pem_private_key(key_path.read_bytes(), password=None)
    require(isinstance(private, Ed25519PrivateKey), 'Ed25519 private PEM required')
    doc = {'schema': SCHEMA, 'version': VERSION, 'commit': commit,
           'reviewer': reviewer, 'publisher': publisher,
           'issuedAt': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
           'files': evidence_inventory(root)}
    raw = json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    sig = private.sign(DOMAIN + raw)
    require(not output.exists() and not signature.exists(), 'never overwrite prior independent review')
    output.parent.mkdir(parents=True, exist_ok=True)
    signature.parent.mkdir(parents=True, exist_ok=True)
    for path, content in ((output, raw), (signature, sig)):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    return {'filesSigned': len(doc['files']), 'reviewer': reviewer, 'status': 'signed-pending-independent-gate'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence-root', type=Path, required=True)
    p.add_argument('--private-key-pem', type=Path, required=True)
    p.add_argument('--reviewer', required=True)
    p.add_argument('--release-operator', required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--approval', type=Path, required=True)
    p.add_argument('--signature', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        print(json.dumps(sign(a.evidence_root, a.private_key_pem, a.reviewer,
                              a.release_operator, a.commit, a.approval, a.signature)))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print('Independent review not signed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

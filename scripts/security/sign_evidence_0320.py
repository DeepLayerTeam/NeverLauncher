#!/usr/bin/env python3
"""Offline, authorized security-signoff step (NOT called by test CI).

Private Ed25519 PKCS#8 key stays on the approver's controlled workstation.
No private key is generated, stored, checked into source or printed by CI.
"""
import argparse
import getpass
import os
from pathlib import Path
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import ga_verify_0320 as ga


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--private-key-file',type=Path,required=True)
    p.add_argument('--commit',required=True)
    p.add_argument('--source-sha256',required=True)
    args=p.parse_args()
    if args.evidence.is_symlink() or args.private_key_file.is_symlink():
        raise SystemExit('refusing symlinked evidence or private key')
    key_stat=args.private_key_file.stat()
    if not stat.S_ISREG(key_stat.st_mode) or (os.name=='posix' and key_stat.st_mode & 0o077):
        raise SystemExit('private key must be an ordinary owner-only file (0600)')
    password=os.environ.get('NEVERLAUNCHER_GA_SIGNING_KEY_PASSPHRASE')
    if password is None:
        password=getpass.getpass('Private key passphrase (empty for unencrypted PKCS#8): ')
    private=serialization.load_pem_private_key(args.private_key_file.read_bytes(), password=password.encode() if password else None)
    if not isinstance(private,Ed25519PrivateKey):
        raise SystemExit('only Ed25519 signing keys accepted')
    raw=args.evidence.read_bytes()
    # Sign the exact approved bytes. Do not alter formatting after signing.
    sig_path=Path(str(args.evidence)+'.sig')
    if sig_path.exists() or sig_path.is_symlink():
        raise SystemExit('signature already exists; remove explicitly after re-review')
    signature=private.sign(ga.DOMAIN+raw)
    try:
        with sig_path.open('x', encoding='ascii') as f:
            f.write(signature.hex()+'\n')
        if os.name=='posix': os.chmod(sig_path,0o600)
        pub=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        ga.verify_evidence(args.evidence,ga.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)), commit=args.commit,source_sha=args.source_sha256,now=ga.dt.datetime.now(ga.dt.timezone.utc))
    except BaseException:
        sig_path.unlink(missing_ok=True)
        raise
    print(f'Approved signed evidence: {args.evidence.name} (.sig); key fingerprint retained by approver')

if __name__=='__main__': main()

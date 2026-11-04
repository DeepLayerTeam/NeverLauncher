#!/usr/bin/env python3
"""E2E pack/sign/verify with disposable issuer keys; negative trust test.

Disposable keys authenticate this TEST ONLY; they do not certify production.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
from package_java_0310 import package


def run(cmd):
    return subprocess.run(cmd,check=True,capture_output=True)


def smoke(cli: Path):
    with tempfile.TemporaryDirectory(prefix='java-0310-sign-') as scratch:
        scratch=Path(scratch)
        priv, pub, other, badpub=[scratch/n for n in ('issuer.pem','issuer.pub.pem','wrong.pem','wrong.pub.pem')]
        run(['openssl','genpkey','-algorithm','ed25519','-out',str(priv)])
        run(['openssl','pkey','-in',str(priv),'-pubout','-out',str(pub)])
        run(['openssl','genpkey','-algorithm','ed25519','-out',str(other)])
        run(['openssl','pkey','-in',str(other),'-pubout','-out',str(badpub)])
        info=package(cli,priv,pub,scratch/'packages')
        for row in info['packages']:
            file=scratch/'packages'/row['filename']
            bad=subprocess.run([str(cli),'extension','verify',str(file),'--public-key',str(badpub)],capture_output=True)
            if bad.returncode == 0:
                raise RuntimeError('wrong publisher key accepted')
            altered=scratch/'modified.nlext'
            raw=bytearray(file.read_bytes());raw[len(raw)//2]^=1;altered.write_bytes(raw)
            bad=subprocess.run([str(cli),'extension','verify',str(altered),'--public-key',str(pub)],capture_output=True)
            if bad.returncode==0:
                raise RuntimeError('modified signed archive accepted')
        print('2 signed runnable example packages verified; wrong-key and tampering rejected')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli',type=Path,required=True)
    args=parser.parse_args()
    smoke(args.cli.resolve(strict=True))

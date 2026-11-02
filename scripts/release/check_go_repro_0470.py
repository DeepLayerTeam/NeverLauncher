#!/usr/bin/env python3
"""Build a real NeverLauncher Go CLI twice with distinct source roots/mtimes.

This is a LOCAL regression, not the externally signed six-target proof.
No simulated executable or provided fixture can satisfy this check.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix='launcher-go-repro-') as temp:
        hashes=[]
        for index in (0,1):
            root=Path(temp)/f'checkout-{index}'
            shutil.copytree(ROOT/'cli',root,ignore=shutil.ignore_patterns('.git','dist','target','node_modules'))
            for path in root.rglob('*.go'):
                os.utime(path,(1700000000+index*300,1700000000+index*300))
            executable=Path(temp)/f'launcher-cli-{index}'
            env=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0')
            completed=subprocess.run(['go','build','-trimpath','-buildvcs=false','-mod=readonly','-o',str(executable),'./cmd/launcher'],
                                     cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            if completed.returncode:
                print('LOCAL GO REPRO BLOCKED: '+completed.stderr[-3000:],file=sys.stderr)
                return 2
            hashes.append(hashlib.sha256(executable.read_bytes()).hexdigest())
        if hashes[0]!=hashes[1]:
            print('LOCAL GO REPRO FAIL: real binaries differ '+str(hashes),file=sys.stderr)
            return 2
        print('LOCAL GO REPRO PASS: real CLI built twice from separate paths and mtimes: '+hashes[0])
    return 0

if __name__=='__main__':raise SystemExit(main())

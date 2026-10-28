#!/usr/bin/env python3
"""Inspect *built* production Desktop and frontend bytes on the active OS.

Called only AFTER cargo build --release and npm run build succeed; never
returns pass for a missing executable or a static manifest-only checkout.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def inspect(binary: Path, frontend: Path, commit: str) -> dict:
    version=(ROOT/'VERSION').read_text().strip()
    if version != '0.35.14' or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('wrong RC version or source commit')
    if not binary.is_file() or binary.is_symlink() or binary.stat().st_size < 1_000_000:
        raise ValueError('no real compiled Desktop binary')
    if os.name != 'nt' and not os.access(binary, os.X_OK):
        raise ValueError('compiled Desktop cannot be executed')
    if not frontend.is_dir() or frontend.is_symlink():
        raise ValueError('compiled frontend directory missing')
    main=frontend/'index.html'
    js=list((frontend/'assets').glob('*.js'))
    if not main.is_file() or not js:
        raise ValueError('no production HTML and JavaScript bundle')
    # Use actual generated artifacts, no source-only or package.json proof.
    files=sorted([main,*js])
    for path in files:
        if path.is_symlink() or path.stat().st_size == 0 or not path.resolve().is_relative_to(frontend.resolve()):
            raise ValueError('unsafe or empty production asset')
    return {'schemaVersion':'neverlauncher.rc.desktop-build.v1','version':version,
            'status':'passed','simulated':False,'commit':commit,
            'platform':platform.system().lower(),'architecture':platform.machine().lower(),
            'binarySha256':sha256(binary),'binarySizeBytes':binary.stat().st_size,
            'frontendAssets':len(files),'frontendSha256':hashlib.sha256(
                ''.join(path.relative_to(frontend).as_posix()+':'+sha256(path)+'\n' for path in files).encode()).hexdigest(),
            'scope':'actual native and production renderer build; does not attest GUI gameplay',
            'timestampUtc':datetime.now(timezone.utc).isoformat()}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--frontend', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--output', type=Path, required=True)
    a=p.parse_args()
    # Never leave a stale passing result after a subsequent failure.
    a.output.unlink(missing_ok=True)
    try:
        result=inspect(a.binary,a.frontend,a.commit)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    except (OSError,ValueError) as e:
        print('Desktop production build BLOCKED: '+str(e),file=sys.stderr)
        return 3
    print('Desktop native and production renderer bytes verified on '+result['platform'])
    return 0

if __name__=='__main__':
    sys.exit(main())

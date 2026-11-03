#!/usr/bin/env python3
"""Validate actually produced six-platform staging payload, never synthesize receipts.

This is not a signing/GA gate: signature and independent operator gates are
mandatory and performed separately by the existing release machinery.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]
CONTRACT=ROOT/'reproducibility/primary-payload-0.47.0.json'


def secure_name(name: str) -> None:
    path=PurePosixPath(name)
    if (not name or name.startswith('/') or '\\' in name or '\\x00' in name or ':' in name
            or '..' in path.parts or any(x == '' for x in name.rstrip('/').split('/'))):
        raise ValueError('unsafe archive member: '+repr(name))


def inspect(path: Path) -> tuple[str,int]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size < 4096:
        raise ValueError('missing/non-production final package: '+path.name)
    if path.name.endswith('.zip'):
        with zipfile.ZipFile(path) as z:
            members=z.infolist()
            if not members: raise ValueError('empty installer: '+path.name)
            for x in members:
                secure_name(x.filename)
                mode=(x.external_attr>>16)&0o170000
                if mode not in (0,stat.S_IFREG,stat.S_IFDIR):
                    raise ValueError('unsafe entry type: '+x.filename)
            bad=z.testzip()
            if bad: raise ValueError('corrupt ZIP entry: '+bad)
    elif path.name.endswith('.tar.gz'):
        with tarfile.open(path,'r:gz') as t:
            members=t.getmembers()
            if not members: raise ValueError('empty installer: '+path.name)
            for x in members:
                secure_name(x.name)
                if not (x.isfile() or x.isdir()):
                    raise ValueError('unsafe TAR entry: '+x.name)
    else:
        raise ValueError('unexpected installer format: '+path.name)
    hash=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):hash.update(chunk)
    return hash.hexdigest(),path.stat().st_size


def inventory(bundle: Path) -> dict:
    version = (ROOT/'VERSION').read_text().strip()
    current_contract = ROOT / 'reproducibility' / f'primary-payload-{version}.json'
    contract=json.loads((current_contract if current_contract.is_file() else CONTRACT).read_text())
    if contract.get('version') != version:
        raise ValueError('wrong release version for primary contract')
    targets=contract.get('targets',{})
    if set(targets)!={'windows-x64','windows-arm64','linux-x64','linux-arm64','darwin-x64','darwin-arm64'}:
        raise ValueError('incomplete six-target contract')
    if not bundle.is_dir() or bundle.is_symlink():raise ValueError('invalid staged release directory')
    result={}
    for target,name in sorted(targets.items()):
        if not isinstance(name,str) or '/' in name or '\\' in name:raise ValueError('invalid package name')
        digest,size=inspect(bundle/name)
        result[target]={'file':name,'sha256':digest,'bytes':size}
    return {'schema':'neverlauncher.payload-observed.v1','version':contract['version'],
            'status':'inspected-not-signed','targets':result}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('staging_dir',type=Path)
    args=p.parse_args()
    try:
        print(json.dumps(inventory(args.staging_dir),indent=2,sort_keys=True))
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,tarfile.TarError) as exc:
        print('PAYLOAD BLOCKED: '+str(exc),file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':raise SystemExit(main())

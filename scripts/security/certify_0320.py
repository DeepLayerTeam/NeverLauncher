#!/usr/bin/env python3
"""Execute mandatory 0.32.0 tests, bound to exact source and Git commit.

No synthetic PASS reports for physical TPM, signed macOS helper or third-party
compatibility are produced. Those need independent, signed live evidence.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
import certify_03114 as previous
TIERS = ('offline', 'backend-security', 'linux-live', 'windows-live')


def source_fingerprint():
    sha=hashlib.sha256()
    # Git's index is the canonical source list in release CI. This avoids
    # fingerprinting generated test output or user-supplied evidence.
    try:
        names=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT,stderr=subprocess.DEVNULL).split(b'\x00')
        paths=[ROOT/os.fsdecode(n) for n in names if n]
    except (FileNotFoundError,subprocess.CalledProcessError):
        paths=[p for p in ROOT.rglob('*') if p.is_file() and not any(d in {'.git','__pycache__','node_modules','.venv','dist','target'} for d in p.relative_to(ROOT).parts)]
    for p in sorted(paths):
        if not p.is_file(): raise ValueError(f'tracked source missing: {p}')
        rel=p.relative_to(ROOT).as_posix()
        sha.update(rel.encode()+b'\x00')
        sha.update(hashlib.sha256(p.read_bytes()).digest())
    return sha.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tier',choices=TIERS,required=True)
    parser.add_argument('--commit',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if not __import__('re').fullmatch('[0-9a-f]{40}',args.commit):
        parser.error('exact Git commit SHA required')
    if (ROOT/'VERSION').read_text().strip()!='0.32.0':
        parser.error('source VERSION must equal 0.32.0')
    if (ROOT/'.git').exists():
        current=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        if current != args.commit: parser.error('release commit is not checked-out HEAD')
        dirty=subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True)
        if dirty.strip(): parser.error('dirty source tree cannot generate GA evidence')
    spec={'offline':previous.OFFLINE,'backend-security':previous.BACKEND_SECURITY,'linux-live':previous.LINUX_LIVE,'windows-live':previous.WINDOWS_LIVE}[args.tier].copy()
    if args.tier=='offline':
        spec['./internal/linuxsandbox']=list(spec['./internal/linuxsandbox'])+['TestGACgroupKillMandatory0320','TestGAConcurrentIPCListenerShutdown0320']
    if args.tier=='windows-live':
        spec['./internal/windowssandbox']=list(spec['./internal/windowssandbox'])+['TestGAInheritedHandlesWhitelisted0320']
    source=source_fingerprint()
    env=os.environ.copy()
    if args.tier=='linux-live': env['NL_RUN_LIVE_LINUX_SANDBOX']='1'
    if args.tier=='windows-live': env['NL_RUN_LIVE_WIN_SANDBOX']='1'
    osname=platform.system()
    required_os={'offline':'Linux','linux-live':'Linux','windows-live':'Windows'}.get(args.tier)
    if required_os and osname!=required_os:
        results=[{'status':'BLOCKED','error':f'{args.tier} requires {required_os}'}]
    else:
        results=[previous.run_test(pkg,tests,env) for pkg,tests in spec.items()]
    status='FAIL' if any(r['status']=='FAIL' for r in results) else 'BLOCKED' if any(r['status']!='PASS' for r in results) else 'PASS'
    report={'schema':'neverlauncher/security-certification/0320', 'productVersion':'0.32.0', 'tier':args.tier,'commit':args.commit,
       'status':status,'sourceSha256':source,'generatedAt':dt.datetime.now(dt.timezone.utc).isoformat(),
       'host':{'system':osname,'architecture':platform.machine(),'release':platform.release()},'results':results}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'tier':args.tier,'status':status,'sourceSha256':source,'report':str(args.output)}))
    return 0 if status=='PASS' else 1

if __name__=='__main__': sys.exit(main())

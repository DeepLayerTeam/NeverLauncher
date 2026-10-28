#!/usr/bin/env python3
"""Execute ACTUAL isolated Docker full-state backup, fresh restore and chaos.

Never uses a production Compose project. Must be launched on a staging host
with real isolated services already running and external writers fenced.
Restores into a DIFFERENT empty project and checks the real readiness endpoint;
this is not evidence of production HA, credential recovery or game E2E.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[2]
DR=ROOT/'scripts/operations/dr_03512.py'
PROJECT=re.compile(r'nl-dr-[a-z0-9][a-z0-9-]{0,35}\Z')

class OperationsBlocked(RuntimeError):pass


def check_args(source: str, target: str, source_url: str, target_url: str, env_file: Path, snapshot: Path):
    if source == target or not PROJECT.fullmatch(source) or not PROJECT.fullmatch(target):
        raise OperationsBlocked('two distinct isolated nl-dr-* Compose projects are required')
    if source_url == target_url:
        raise OperationsBlocked('source and restored target must use distinct readiness endpoints')
    for url in (source_url,target_url):
        p=urlsplit(url)
        if p.scheme!='http' or p.hostname not in ('127.0.0.1','localhost') or not p.port or p.path!='/ready' or p.query or p.fragment or p.username or p.password:
            raise OperationsBlocked('real source/target readiness must use loopback HTTP /ready')
    if not env_file.is_file() or env_file.is_symlink():
        raise OperationsBlocked('isolated environment file missing or symlinked')
    if snapshot.exists() or snapshot.is_symlink():
        raise OperationsBlocked('fresh snapshot destination required; refusing overwrite')
    if os.environ.get('NEVERLAUNCHER_RC_DR_ISOLATED')!='YES':
        raise OperationsBlocked('explicit staging-only acknowledgment required')


def actual(*args: str, timeout: int=3600) -> dict:
    # No shell or secrets in process output / saved evidence.
    try:
        proc=subprocess.run([sys.executable,str(DR),*map(str,args)],cwd=ROOT,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            timeout=timeout,check=False)
    except (subprocess.TimeoutExpired,OSError) as exc:
        raise OperationsBlocked('actual DR operation could not complete') from exc
    if proc.returncode or len(proc.stdout)>4*1024*1024:
        raise OperationsBlocked('actual DR command failed or returned oversized evidence')
    try:
        value=json.loads(proc.stdout)
    except ValueError as exc:
        raise OperationsBlocked('DR command did not return JSON') from exc
    if not isinstance(value,dict):
        raise OperationsBlocked('DR result is not an object')
    return value


def run(source: str, target: str, env_file: Path, snapshot: Path,
        source_ready: str, target_ready: str, network_ha: bool=False,
        s3_source: str|None=None, s3_target: str|None=None, s3_endpoint: str|None=None) -> dict:
    check_args(source,target,source_ready,target_ready,env_file,snapshot)
    if network_ha and (not s3_source or not s3_target or s3_source==s3_target):
        raise OperationsBlocked('network-ha requires distinct source/target S3 buckets')
    common=['--env-file',str(env_file)] + (['--network-ha'] if network_ha else [])
    backup=['backup','--project',source,'--confirm',source,'--snapshot',str(snapshot),*common]
    if network_ha:
        backup += ['--s3-source-bucket',s3_source]
        if s3_endpoint:backup+=['--s3-endpoint',s3_endpoint]
    b=actual(*backup)
    if b.get('version')!='0.35.14' or b.get('sourceProject')!=source or not b.get('files'):
        raise OperationsBlocked('real DR backup not verified as current source snapshot')
    v=actual('verify','--snapshot',str(snapshot),*(['--network-ha'] if network_ha else []))
    if v.get('status')!='verified' or v.get('manifest',{}).get('sourceProject')!=source:
        raise OperationsBlocked('snapshot verification failed')
    restore=['restore-fresh','--project',target,'--confirm',target,'--snapshot',str(snapshot),
             '--ready-url',target_ready,*common]
    if network_ha:
        restore+=['--target-s3-bucket',s3_target]
        if s3_endpoint:restore+=['--s3-endpoint',s3_endpoint]
    r=actual(*restore)
    if r.get('status')!='restored-and-started' or r.get('source')!=source or r.get('target')!=target or r.get('applicationVerified') is not True:
        raise OperationsBlocked('fresh site not application-verified')
    c=actual('chaos','--project',source,'--confirm',source,'--snapshot',str(snapshot),
             '--ready-url',source_ready,*common)
    expected={'postgres','api'}|({'redis'} if network_ha else set())
    events=c.get('events',[])
    if c.get('status')!='measured' or c.get('project')!=source or not isinstance(events,list) or {v.get('service') for v in events if isinstance(v,dict)}!=expected:
        raise OperationsBlocked('actual isolated service failure checks incomplete')
    if not isinstance(r.get('rtoSeconds'),(int,float)) or r['rtoSeconds']<=0:
        raise OperationsBlocked('missing measured restore duration')
    return {'schemaVersion':'neverlauncher.rc.operations.v1','status':'recovery-exercised',
            'version':'0.35.14','source':source,'target':target,'storage':b['storage'],
            'snapshotManifestSha256':hashlib.sha256((snapshot/'manifest.json').read_bytes()).hexdigest(),
            'freshSiteReady':True,'rtoSeconds':r['rtoSeconds'],
            'chaosServices':sorted(expected),'networkHA':network_ha,
            'realBackendHAProven':False,'rpoVerified':False,'credentialsRestoredFromSecretManager':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True)
    parser.add_argument('--target',required=True)
    parser.add_argument('--env-file',type=Path,required=True)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--source-ready-url',required=True)
    parser.add_argument('--target-ready-url',required=True)
    parser.add_argument('--network-ha',action='store_true')
    parser.add_argument('--s3-source-bucket')
    parser.add_argument('--s3-target-bucket')
    parser.add_argument('--s3-endpoint')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        receipt=run(args.source,args.target,args.env_file,args.snapshot,args.source_ready_url,
                    args.target_ready_url,args.network_ha,args.s3_source_bucket,args.s3_target_bucket,args.s3_endpoint)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    except (OperationsBlocked,ValueError,OSError,KeyError) as exc:
        print('0.35.14 isolated operations BLOCKED: '+str(exc),file=sys.stderr)
        return 3
    print('Real fresh-site restore and isolated failure injection completed; HA/production RPO NOT certified.')
    return 0

if __name__=='__main__':sys.exit(main())

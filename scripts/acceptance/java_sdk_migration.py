#!/usr/bin/env python3
"""Execute and replay the 0.52.8 Java, SDK and migration acceptance.

Local exercises actual Java subprocesses, Go/TS/Java HTTP clients and migration
negative tests. Live invokes the existing three-project Gravit GA verifier (36
live checks and 19 module probes), the installed JVM Host and both historical
NeverLauncher upgrade witnesses; all must operate on real external systems.
Missing infrastructure FAILS, not a fabricated pass or an optional skip.
Reports are private and are not independent production GA signatures.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
from legacy_upgrade_real_0528 import private_json, sha_file, require, Blocked
from java_host_real_0528 import run as java_host_run
import legacy_upgrade_real_0528 as legacy

SCHEMA='neverlauncher.java-sdk-migration-0528/v1'
SOURCE_RE=re.compile('[0-9a-f]{40}\\Z')


def private_save(path: Path, obj):
    require(path.is_absolute() and path.parent.is_dir() and not path.parent.is_symlink()
            and not path.exists() and not path.is_symlink(), 'new private output required')
    raw=(json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True)+'\n').encode()
    fd=os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def command(args, *, timeout, cwd=ROOT):
    # Fixed, audited commands. No shell, no arbitrary probe programs, and
    # no unbounded stdout or inclusion of sensitive provider environment.
    env={k:v for k,v in os.environ.items() if not any(t in k.upper() for t in
         ('TOKEN','SECRET','PASSWORD','SIGNING','PRIVATE','DSN','CREDENTIAL','AUTH'))}
    env.pop('PYTHONPATH',None)
    try:
        result=subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=True)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise Blocked('required executable regression failed: '+ ' '.join(Path(x).name for x in args[:3])) from exc
    require(len(result.stdout)+len(result.stderr)<(8<<20), 'unbounded local test output')
    return hashlib.sha256(result.stdout+result.stderr).hexdigest()


def local():
    checks={}
    checks['five-real-jvm-customizations'] = command(
        ['sh','examples/extensions/gravit-five-0495/build.sh','test'], timeout=150)
    checks['java-http-client'] = command(['sh','sdk/java/http-client/build.sh','test'],timeout=110)
    checks['go-http-client'] = command(['go','test','-count=1','./...'], timeout=90, cwd=ROOT/'sdk/api/go')
    checks['typescript-build'] = command(['tsc','-p','tsconfig.json'], timeout=60, cwd=ROOT/'sdk/api/typescript')
    checks['typescript-http-client'] = command(
        ['node','--test','test/client.test.mjs','test/binary_0461.test.mjs'], timeout=75, cwd=ROOT/'sdk/api/typescript')
    checks['gravit-three-project-negative-regression'] = command(
        [sys.executable,'-m','unittest','discover','-s','tools/gravit-port',
         '-p','test_rehearse_cohort_04910.py'], timeout=75)
    checks['gravit-live-verifier-negative-regression'] = command(
        [sys.executable,'-m','unittest','discover','-s','tools/gravit-port',
         '-p','test_ga_acceptance_0500.py'], timeout=120)
    checks['legacy-and-java-negative-regression'] = command(
        [sys.executable,'-m','unittest','discover','-s','scripts/acceptance',
         '-p','test_java_sdk_migration_0528.py'], timeout=75)
    return {'format':SCHEMA, 'productVersion':(ROOT/'VERSION').read_text().strip(), 'status':'LOCAL_REGRESSIONS_NOT_GA',
            'checks':checks, 'gaCertified':False}


def parse_live(cfg):
    require(cfg.get('format') == SCHEMA and SOURCE_RE.fullmatch(str(cfg.get('sourceCommit',''))),
            'exact source commit and schema required')
    require(type(cfg.get('gravit')) is dict and type(cfg.get('java')) is dict and
            type(cfg.get('legacy')) is list and len(cfg['legacy'])==2,
            'live Java, three Gravit and two legacy migrations required')
    versions=[entry.get('sourceVersion') for entry in cfg['legacy'] if type(entry) is dict]
    require(sorted(versions)==['0.36.0','0.46.0'], 'both historical NeverLauncher routes required')
    require(len({str(entry.get('capture')) for entry in cfg['legacy']}) == 2,
            'legacy input receipts must be distinct')
    return cfg


def live_run(cfg):
    cfg=parse_live(cfg)
    sha=cfg['sourceCommit']
    java_config=private_json(Path(cfg['java']['config']))
    require(java_config.get('sourceCommit') == sha, 'Java host commit differs from release')
    java_out=Path(cfg['java']['output'])
    java_result=java_host_run(java_config,java_out)
    require(java_result.get('status') == 'LIVE_CHECKS_PASSED_REVIEW_REQUIRED'
            and java_result.get('sourceCommit') == sha and len(java_result.get('checks',[])) >= 6,
            'five real installed Java customizations were not witnessed')
    grav=cfg['gravit']
    grav_cfg=Path(grav['config'])
    grav_dir=Path(grav['evidenceDir'])
    private_json(grav_cfg)
    require(grav_dir.is_absolute() and grav_dir.is_dir() and grav_dir.stat().st_mode & 0o077 == 0
            and not any(grav_dir.iterdir()), 'real Gravit evidence directory must be new, private and empty')
    try:
        subprocess.run([sys.executable,str(ROOT/'tools/gravit-port/ga_acceptance_0500.py'),
                        '--config',str(grav_cfg),'--evidence-dir',str(grav_dir)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=4200, check=True)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise Blocked('real three-project Gravit verification failed') from exc
    grav_report=private_json(grav_dir/'acceptance-0500.json')
    classes={'fileauth-single','sql-modded','proxy-network'}
    require(grav_report.get('status')=='LIVE_CHECKS_PASSED_REVIEW_REQUIRED'
            and grav_report.get('migrationChecks')==36 and grav_report.get('moduleCheckCount')==19
            and set(row['referenceClass'] for row in grav_report.get('references',[])) == classes
            and grav_report.get('productionGA') is False,
            'full external Gravit migration and module evidence not verified')
    require(grav_report.get('commitSha') == sha, 'Java and Gravit source commit mismatch')
    legacy_results={}
    for route in cfg['legacy']:
        source_version=route['sourceVersion']
        path=Path(route['config'])
        captured=Path(route['capture'])
        output=Path(route['output'])
        legacy_cfg=private_json(path)
        original=private_json(captured)
        require(legacy_cfg.get('sourceVersion')==source_version,
                'legacy route does not match original installation')
        legacy_cfg['sourceCaptureSha256']=sha_file(str(captured))
        result=legacy.verify(legacy_cfg,original)
        require(result.get('status')=='LIVE_CHECKS_PASSED_REVIEW_REQUIRED' and
                result.get('sourceVersion')==source_version, 'legacy live check blocked')
        private_save(output,result)
        legacy_results[source_version]=sha_file(str(output))
    return {'format':SCHEMA,'productVersion':(ROOT/'VERSION').read_text().strip(),'sourceCommit':sha,
            'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED','gaCertified':False,
            'java':{'evidenceSha256':sha_file(str(java_out)), 'checks':len(java_result['checks'])},
            'gravit':{'evidenceSha256':sha_file(str(grav_dir/'acceptance-0500.json')),
                      'classes':sorted(classes),'migrationChecks':36,'moduleChecks':19},
            'legacy':legacy_results, 'completedAt':datetime.now(timezone.utc).isoformat()}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=('local','live'))
    ap.add_argument('--config',type=Path)
    ap.add_argument('--report',type=Path,required=True)
    args=ap.parse_args(argv)
    os.umask(0o077)
    try:
        require(tuple(map(int, (ROOT/'VERSION').read_text().strip().split('.')[:3])) >= (0,52,8), 'checkout version is too old')
        result=local() if args.mode=='local' else live_run(private_json(args.config))
        private_save(args.report,result)
        print('0.52.8', result['status'], len(result.get('checks',{})))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
        print('BLOCKED 0.52.8:',type(exc).__name__,str(exc),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())

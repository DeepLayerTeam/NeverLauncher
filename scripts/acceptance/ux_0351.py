#!/usr/bin/env python3
"""Executable 0.35.1 G/M user-journey inventory and local acceptance runner.

Local test success NEVER means a real Minecraft, Desktop or signed GA certification.
The runtime reads existing test implementations; there are no synthetic green probes.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
CATALOG = Path('compatibility/gravit/user-journeys-0351.json')
IDS = [f'G{i:02}' for i in range(1, 36)] + [f'M{i:02}' for i in range(1, 20)]
UX = {
    'UX01': ['G07', 'G13', 'G30', 'G31', 'M07', 'M11'],
    'UX02': ['G01', 'G07', 'G08', 'G21', 'G31', 'G32', 'M07'],
    'UX03': ['G10', 'G11', 'G22', 'G25'],
    'UX04': ['G30', 'G31', 'M07', 'M11'],
    'UX05': ['G26', 'G27', 'M17'],
    'UX06': ['G31', 'M07', 'M10'],
    'UX07': ['G05', 'G06', 'G18', 'G29', 'M09'],
    'UX08': ['G08', 'G09', 'G11', 'G25'],
    'UX09': ['G11', 'G22', 'G31', 'M04'],
    'UX10': ['G17', 'G20', 'G22', 'G34'],
    'UX11': ['G34', 'M13', 'M14', 'M15'],
    'UX12': IDS,
}
ALLOWED = ('services/', 'cli/', 'prestarter/', 'runtime/', 'apps/', 'scripts/', 'e2e/', 'sdk/', 'compatibility/')


class AuditError(Exception):
    pass


def require(ok, message):
    if not ok:
        raise AuditError(message)


def referenced_file(path):
    """Resolve an audit ref without traversing outside the source checkout."""
    require(isinstance(path, str) and path.startswith(ALLOWED) and not path.startswith('/') and '\\' not in path and '..' not in Path(path).parts,
            'unexpected source/test path: ' + repr(path))
    ref = (ROOT / path).resolve()
    require(ref.is_relative_to(ROOT) and ref.is_file(), 'missing or escaping source/test path: ' + path)
    return ref


def load_inventory():
    data = json.loads((ROOT / CATALOG).read_text(encoding='utf-8'))
    require(data.get('schemaVersion') == 'neverlauncher.user-journeys.v1', 'wrong catalog format')
    require(data.get('productVersion') == '0.35.1', 'wrong catalog version')
    require((ROOT/'VERSION').read_text().strip() == '0.35.1', 'VERSION is not 0.35.1')
    journeys = data.get('journeys')
    require(isinstance(journeys, list) and [x.get('id') for x in journeys] == IDS,
            'required ordered unique G01-G35 + M01-M19 coverage missing')
    sources = data['baseline']
    require(set(sources) == {'G', 'M'}, 'missing historical baseline')
    g = json.loads(referenced_file(sources['G']).read_text())['requirements']
    m = json.loads(referenced_file(sources['M']).read_text())['modules']
    upstream = {x['id']: x for x in g+m}
    require(set(upstream) == set(IDS), 'baseline G/M identities changed')
    for j in journeys:
        ident = j['id']
        require(j.get('name') == upstream[ident].get('name', upstream[ident].get('upstreamModule')),
                'upstream name changed: '+ident)
        require(j.get('legacyStatus') == upstream[ident].get('status'), 'historic status mismatch: '+ident)
        require(j.get('actor') in ('player', 'owner', 'operator'), 'missing actor: '+ident)
        for field in ('entry', 'action', 'success', 'negative', 'limitations'):
            require(isinstance(j.get(field), str) and len(j[field].strip()) >= 8, ident+' missing '+field)
        require(j.get('operatorStep') == 'none' or j.get('operatorStep', '').startswith(('advanced:', 'prohibited:')), 'bad operator work classification: '+ident)
        require(j.get('verification') == 'not-run', 'catalog cannot contain claims of verification: '+ident)
        require(j.get('acceptanceScope') in ('local-plus-target', 'target-required', 'security-exclusion'),
                'invalid acceptance scope: '+ident)
        require(isinstance(j.get('testRefs'), list) and j['testRefs'], 'missing executable probe refs: '+ident)
        for f in j['testRefs'] + j['implementationRefs']:
            referenced_file(f)
        require(all(str(f).endswith(('.go','.py','.mjs','.sh')) for f in j['testRefs']),
                'non-executable test ref: '+ident)
        if ident == 'M17':
            require(j['acceptanceScope'] == 'security-exclusion' and j['operatorStep'].startswith('prohibited:'),
                    'M17 unsafe behavior must be explicitly forbidden')
    require(set(UX) == {f'UX{i:02}' for i in range(1,13)}, 'UX mapping incomplete')
    require(all(set(ids) <= set(IDS) and ids for ids in UX.values()), 'UX orphan references')
    return journeys


def plan_test(path):
    """Dispatch ONLY existing test files, never shell-evaluate catalog data."""
    ref = referenced_file(path)
    if path.endswith('_test.go') or path.endswith('test.go'):
        # Go package tests execute in their existing module context. The selected
        # test file cannot be built alone without its production package.
        module = ref.parent
        while module != ROOT and not (module / 'go.mod').is_file():
            module = module.parent
        require(module != ROOT, 'missing Go module for: '+path)
        pkg = './' + ref.parent.relative_to(module).as_posix()
        return ((str(module), pkg), ['go','test','-count=1','-timeout=12m',pkg], module)
    if path.endswith('.test.mjs') or path.endswith('.test.js'):
        return ((path,), ['node','--experimental-strip-types','--test',str(ref)], ROOT)
    if path.endswith('.py') and 'test_' in ref.name:
        return ((path,), [sys.executable,str(ref)], ROOT)
    if path.endswith('.sh'):
        # E2E shell scripts require explicitly provisioned machines and are not
        # assumed safe to execute in a local acceptance run.
        return None
    raise AuditError('unknown probe execution format: '+path)


def atomic_report(path, data):
    path = path.resolve()
    path.parent.mkdir(parents=True,exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.ux0351-',dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump(data,f,indent=2,sort_keys=True,ensure_ascii=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def execute(journeys, ids, timeout, report):
    require(0 < timeout <= 1800, 'timeout must be 1..1800 seconds')
    selected=[x for x in journeys if x['id'] in ids]
    require(len(selected) == len(ids), 'unknown requirement selected')
    runs={}
    for journey in selected:
        for path in journey['testRefs']:
            planned=plan_test(path)
            if planned is None:
                continue
            key,cmd,cwd=planned
            key='::'.join(key)
            if key in runs:
                continue
            print('Executing production test:', ' '.join(cmd), flush=True)
            try:
                # No shell, no credentials/keys serialized in evidence, output is
                # hashed but not stored because test logs may contain secrets.
                result=subprocess.run(cmd,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT,timeout=timeout,check=False)
                blob=result.stdout
                runs[key]={'status':'passed' if result.returncode==0 else 'failed',
                           'exitCode':result.returncode,'outputSha256':hashlib.sha256(blob).hexdigest(),
                           'outputBytes':len(blob),'command':cmd,'testRefs':[path]}
                if result.returncode:
                    print('FAILED:',path,'(output withheld; rerun directly for diagnostics)',file=sys.stderr)
            except (OSError,subprocess.TimeoutExpired) as e:
                runs[key]={'status':'blocked','reason':'execution unavailable or timed out',
                           'testRefs':[path], 'command':cmd}
                print('BLOCKED:',path,type(e).__name__,file=sys.stderr)
    outcome=[]
    for j in selected:
        runnable=[plan_test(p) for p in j['testRefs']]
        keys=['::'.join(p[0]) for p in runnable if p is not None]
        statuses=[runs[k]['status'] for k in keys]
        # A passed package-level Go test is still only local regression evidence.
        status='local-regression-passed' if statuses and all(s=='passed' for s in statuses) else ('failed' if 'failed' in statuses else 'blocked')
        outcome.append({'id':j['id'],'status':status,'userJourneyVerified':False,
                        'localTests':len(statuses),'reason':'Real GUI/target operations require independent execution.'})
    document={'schemaVersion':'neverlauncher.user-acceptance-result.v1', 'version':'0.35.1',
              'createdAt':datetime.now(timezone.utc).isoformat(),
              'catalogSha256':hashlib.sha256((ROOT/CATALOG).read_bytes()).hexdigest(),
              'targetVerified':False,'realMinecraftCertification':False,
              'results':outcome,'testRuns':runs}
    atomic_report(report,document)
    failed=sum(x['status']!='local-regression-passed' for x in outcome)
    print(f'Local G/M regression: {len(outcome)-failed}/{len(outcome)} passed; target verification: NOT RUN')
    return 1 if failed else 0


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['audit','run'])
    p.add_argument('--ids',default='',help='comma-separated G/M IDs for run; default all')
    p.add_argument('--timeout',type=int,default=900)
    p.add_argument('--report',type=Path,help='required for run, keep outside repository')
    args=p.parse_args(argv)
    try:
        journeys=load_inventory()
        if args.command=='audit':
            counts=Counter(x['acceptanceScope'] for x in journeys)
            print(f'0.35.1 AUDIT PASS: {len(journeys)} G/M journeys, UX01-UX12 mapped, all probe files exist')
            print('Scopes:',dict(counts),'| not-run:',len(journeys),'| target verified: 0')
            return 0
        require(args.report is not None, 'run requires --report')
        ids = [s.strip().upper() for s in args.ids.split(',')] if args.ids else IDS
        require(len(ids)==len(set(ids)) and set(ids) <= set(IDS), 'invalid or duplicate --ids')
        return execute(journeys,ids,args.timeout,args.report)
    except (AuditError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print('UX0351 BLOCKED:',exc,file=sys.stderr)
        return 2


if __name__=='__main__':
    sys.exit(main())

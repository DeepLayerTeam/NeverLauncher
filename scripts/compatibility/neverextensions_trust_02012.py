#!/usr/bin/env python3
"""Fail-closed public compatibility matrix builder for NeverExtensions 0.20.12."""
from __future__ import annotations
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DEFAULT_TARGETS=ROOT/'neverextensions/trust-recovery-targets-02012.json'

def load(path:Path): return json.loads(path.read_text(encoding='utf-8'))
def validate_targets(path:Path):
    doc=load(path); rows=doc.get('targets',[]); checks=doc.get('requiredChecks',[])
    ids=[r.get('id') for r in rows]
    if doc.get('schemaVersion')!='1.0' or not rows or len(ids)!=len(set(ids)) or not checks:
        raise SystemExit('invalid NeverExtensions trust/recovery target definition')
    required={r.get('os') for r in rows if r.get('required')}
    if required != {'linux','windows','macos'}:
        raise SystemExit(f'required cross-platform OS set must be linux/windows/macos, got {sorted(required)}')
    print(f'NeverExtensions 0.20.12 targets OK: {len(rows)} required platforms')
    return doc

def aggregate(targets:Path, evidence_dir:Path, out_json:Path, out_md:Path):
    doc=validate_targets(targets); checks=doc['requiredChecks']; results=[]
    for target in doc['targets']:
        p=evidence_dir/f"{target['id']}.json"
        if not p.is_file(): raise SystemExit(f'missing evidence: {p}')
        e=load(p)
        if e.get('targetId')!=target['id'] or e.get('os')!=target['os'] or e.get('status')!='pass':
            raise SystemExit(f'invalid/non-PASS evidence for {target["id"]}')
        got=e.get('checks',{})
        missing=[c for c in checks if got.get(c) is not True]
        if missing: raise SystemExit(f'{target["id"]} missing checks: {missing}')
        results.append(e)
    matrix={'schemaVersion':'1.0','productVersion':(ROOT/'VERSION').read_text().strip(),'feature':doc['feature'],'generatedAt':datetime.now(timezone.utc).isoformat(),'status':'certified','targets':results}
    out_json.parent.mkdir(parents=True,exist_ok=True); out_json.write_text(json.dumps(matrix,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    lines=['# NeverExtensions Trust, Recovery & Certification — public compatibility matrix','',f"Version: `{matrix['productVersion']}`  ",f"Status: **{matrix['status']}**",'', '| Target | OS | Architecture | Go | Status |','| --- | --- | --- | --- | --- |']
    for e in results: lines.append(f"| `{e['targetId']}` | {e['os']} | {e.get('arch','')} | {e.get('goVersion','')} | **PASS** |")
    lines += ['','PASS is emitted only from CI evidence after all required trust/recovery, malicious-package, build and OpenAPI checks complete on that runner.','']
    out_md.write_text('\n'.join(lines),encoding='utf-8')
    print(f'NeverExtensions public matrix certified: {len(results)}/{len(results)}')

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest='cmd',required=True)
    v=sub.add_parser('validate'); v.add_argument('--targets',type=Path,default=DEFAULT_TARGETS)
    a=sub.add_parser('aggregate'); a.add_argument('--targets',type=Path,default=DEFAULT_TARGETS); a.add_argument('--evidence-dir',type=Path,required=True); a.add_argument('--out-json',type=Path,required=True); a.add_argument('--out-md',type=Path,required=True)
    ns=ap.parse_args()
    if ns.cmd=='validate': validate_targets(ns.targets)
    else: aggregate(ns.targets,ns.evidence_dir,ns.out_json,ns.out_md)
if __name__=='__main__': main()

#!/usr/bin/env python3
"""Отказ с блокировкой NeverExtensions 0.21.0 GA compatibility/certificate builder."""
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DEFAULT_TARGETS=ROOT/'neverextensions/ga-targets-0210.json'

def load(path:Path): return json.loads(path.read_text(encoding='utf-8'))
def sha256(path:Path): return hashlib.sha256(path.read_bytes()).hexdigest()

def validate_targets(path:Path):
    doc=load(path); rows=doc.get('targets',[]); checks=doc.get('requiredChecks',[]); contract=doc.get('contract',{})
    ids=[r.get('id') for r in rows]
    if doc.get('schemaVersion')!='1.0' or doc.get('feature')!='NeverExtensions GA' or not rows or len(ids)!=len(set(ids)) or not checks:
        raise SystemExit('invalid NeverExtensions GA target definition')
    if {r.get('os') for r in rows if r.get('required')} != {'linux','windows','macos'}:
        raise SystemExit('required NeverExtensions GA OS set must be linux/windows/macos')
    expected={'packageFormatVersion':'1.0','manifestSchemaVersion':'2.0','hostProtocolVersion':'1.0','extensionApiVersion':'1.0'}
    if any(contract.get(k)!=v for k,v in expected.items()) or contract.get('legacyApiAliases')!=['3.7']:
        raise SystemExit('NeverExtensions GA frozen contract mismatch')
    if (ROOT/'VERSION').read_text().strip()!='0.21.0':
        raise SystemExit('NeverExtensions GA certification requires VERSION=0.21.0')
    print(f'NeverExtensions GA targets OK: {len(rows)} required platforms, {len(checks)} checks')
    return doc

def aggregate(targets:Path,evidence_dir:Path,out_json:Path,out_md:Path,out_certificate:Path):
    doc=validate_targets(targets); checks=doc['requiredChecks']; results=[]; evidence_hashes={}
    for target in doc['targets']:
        p=evidence_dir/f"{target['id']}.json"
        if not p.is_file(): raise SystemExit(f'missing evidence: {p}')
        e=load(p)
        if e.get('targetId')!=target['id'] or e.get('os')!=target['os'] or e.get('status')!='pass':
            raise SystemExit(f'invalid/non-PASS evidence for {target["id"]}')
        missing=[c for c in checks if e.get('checks',{}).get(c) is not True]
        if missing: raise SystemExit(f'{target["id"]} missing checks: {missing}')
        if e.get('contract') != doc['contract']: raise SystemExit(f'{target["id"]} contract mismatch')
        results.append(e); evidence_hashes[target['id']]=sha256(p)
    generated=datetime.now(timezone.utc).isoformat()
    matrix={'schemaVersion':'1.0','productVersion':'0.21.0','feature':doc['feature'],'contract':doc['contract'],'generatedAt':generated,'status':'certified','targets':results}
    out_json.parent.mkdir(parents=True,exist_ok=True); out_json.write_text(json.dumps(matrix,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    lines=['# NeverExtensions GA — public compatibility matrix','', 'Version: `0.21.0`  ','Status: **certified**','', '| Target | OS | Architecture | Go | Status |','| --- | --- | --- | --- | --- |']
    for e in results: lines.append(f"| `{e['targetId']}` | {e['os']} | {e.get('arch','')} | {e.get('goVersion','')} | **PASS** |")
    lines += ['','The certificate is emitted only after every required GA check has PASS evidence on Linux, Windows and macOS.','']
    out_md.write_text('\n'.join(lines),encoding='utf-8')
    cert={'schemaVersion':'1.0','productVersion':'0.21.0','feature':'NeverExtensions GA','status':'certified','generatedAt':generated,'contract':doc['contract'],'matrixSHA256':sha256(out_json),'evidenceSHA256':evidence_hashes,'targets':sorted(evidence_hashes)}
    out_certificate.write_text(json.dumps(cert,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(f'NeverExtensions GA certified: {len(results)}/{len(results)} targets')

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest='cmd',required=True)
    v=sub.add_parser('validate'); v.add_argument('--targets',type=Path,default=DEFAULT_TARGETS)
    a=sub.add_parser('aggregate'); a.add_argument('--targets',type=Path,default=DEFAULT_TARGETS); a.add_argument('--evidence-dir',type=Path,required=True); a.add_argument('--out-json',type=Path,required=True); a.add_argument('--out-md',type=Path,required=True); a.add_argument('--out-certificate',type=Path,required=True)
    ns=ap.parse_args()
    if ns.cmd=='validate': validate_targets(ns.targets)
    else: aggregate(ns.targets,ns.evidence_dir,ns.out_json,ns.out_md,ns.out_certificate)
if __name__=='__main__': main()

#!/usr/bin/env python3
"""Fail CI when canonical Go routes and the checked-in OpenAPI contract diverge."""
from __future__ import annotations
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SPEC=ROOT/'schemas/openapi.yaml'
HTTP=ROOT/'services/api/internal/httpapi'
try: spec=json.loads(SPEC.read_text())
except Exception as exc: raise SystemExit(f"OpenAPI parse failed: {exc}")
errors=[]
if spec.get('openapi')!='3.1.1': errors.append('openapi must be 3.1.1')
if spec.get('info',{}).get('version')!='1.0.0': errors.append('info.version must be 1.0.0')
route_re=re.compile(r'"(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^" ]+|/api/profiles/minecraft/[^" ]+|/authserver/[^" ]+|/sessionserver/session/minecraft/[^" ]+|/(?:health|ready|metrics))')
files=[HTTP/'handler.go']+sorted(p for p in HTTP.glob('routes_*.go') if 'legacy' not in p.name)
code=set()
for f in files:
    for method,path in route_re.findall(f.read_text()): code.add((method.lower(),path.replace('{path...}','{path}')))
doc=set()
ids=[]
for path,item in spec.get('paths',{}).items():
    if re.search(r'/api/v[2-9](?:/|$)',path): errors.append(f'historical route in canonical OpenAPI: {path}')
    for method,op in item.items():
        if method.lower() not in {'get','post','put','patch','delete'}: continue
        key=(method.lower(),path); doc.add(key)
        oid=op.get('operationId')
        if not oid: errors.append(f'{method.upper()} {path} missing operationId')
        else: ids.append(oid)
        if not op.get('responses'): errors.append(f'{method.upper()} {path} missing responses')
        for name in re.findall(r'{([^}]+)}',path):
            params=op.get('parameters',[])
            if not any(p.get('in')=='path' and p.get('name')==name and p.get('required') is True for p in params):
                errors.append(f'{method.upper()} {path} missing required path parameter {name}')
for missing in sorted(code-doc): errors.append(f'route missing from OpenAPI: {missing[0].upper()} {missing[1]}')
for extra in sorted(doc-code): errors.append(f'OpenAPI operation missing from canonical router: {extra[0].upper()} {extra[1]}')
if len(ids)!=len(set(ids)): errors.append('operationId values must be unique')
# P3 invariant: historical routers are physically removed from the canonical server.
config=(HTTP/'handler.go').read_text()
if 'registerLegacy' in config or 'EnableLegacyAPI' in config: errors.append('legacy API registration must be removed in P3')
if errors:
    print('OpenAPI contract validation FAILED:',file=sys.stderr)
    for e in errors: print(' - '+e,file=sys.stderr)
    raise SystemExit(1)
print(f'OpenAPI contract validation OK: {len(code)} canonical operations, version 1.0.0')

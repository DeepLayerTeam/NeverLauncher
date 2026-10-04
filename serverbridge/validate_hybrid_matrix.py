#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
d=json.loads((ROOT/'serverbridge/hybrid-targets.json').read_text())
expected={'mohist','arclight','magma','catserver','banner','cardboard'}
rows=d.get('targets') or []
ids={r.get('id') for r in rows}
if d.get('productVersion')!=(ROOT/'VERSION').read_text().strip(): raise SystemExit('hybrid matrix version drift')
if ids!=expected: raise SystemExit(f'hybrid matrix target drift: {ids}')
if any(r.get('status')!='not-certified' for r in rows): raise SystemExit('0.19.8 universal release must not certify hybrid cores')
print('hybrid certification matrix: fail-closed OK')

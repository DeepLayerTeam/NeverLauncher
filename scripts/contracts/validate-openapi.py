#!/usr/bin/env python3
"""Завершает CI с ошибкой при расхождении канонических маршрутов Go и сохранённого в репозитории контракта OpenAPI."""
from __future__ import annotations
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SPEC=ROOT/'schemas/openapi.yaml'
HTTP=ROOT/'services/api/internal/httpapi'
try: spec=json.loads(SPEC.read_text(encoding="utf-8"))
except Exception as exc: raise SystemExit(f"Ошибка: «разбор OpenAPI»: {exc}")
errors=[]
if spec.get('openapi')!='3.1.1': errors.append('Версия OpenAPI должна быть 3.1.1')
if spec.get('info',{}).get('version')!='1.0.0': errors.append('Поле info.version должно быть равно 1.0.0')
route_re=re.compile(r'"(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^" ]+|/api/profiles/minecraft(?:/[^" ]+)?|/api/user/profile/[^" ]+|/authserver/[^" ]+|/sessionserver/session/minecraft/[^" ]+|/(?:health|ready|metrics))')
files=[HTTP/'handler.go']+sorted(p for p in HTTP.glob('routes_*.go') if 'legacy' not in p.name)+sorted(p for p in HTTP.glob('migration_*.go') if not p.name.endswith('_test.go'))
code=set()
for f in files:
    for method,path in route_re.findall(f.read_text(encoding="utf-8")): code.add((method.lower(),path.replace('{path...}','{path}')))
doc=set()
ids=[]
for path,item in spec.get('paths',{}).items():
    if re.search(r'/api/v[2-9](?:/|$)',path): errors.append(f'Устаревший маршрут в каноническом OpenAPI: {path}')
    for method,op in item.items():
        if method.lower() not in {'get','post','put','patch','delete'}: continue
        key=(method.lower(),path); doc.add(key)
        oid=op.get('operationId')
        if not oid: errors.append(f'{method.upper()} {path}: отсутствует operationId')
        else: ids.append(oid)
        if not op.get('responses'): errors.append(f'{method.upper()} {path}: отсутствуют ответы responses')
        for name in re.findall(r'{([^}]+)}',path):
            params=op.get('parameters',[])
            if not any(p.get('in')=='path' and p.get('name')==name and p.get('required') is True for p in params):
                errors.append(f'{method.upper()} {path} отсутствует обязательный параметр пути {name}')
for missing in sorted(code-doc): errors.append(f'Маршрут отсутствует в OpenAPI: {missing[0].upper()} {missing[1]}')
for extra in sorted(doc-code): errors.append(f'Операция OpenAPI отсутствует в основном маршрутизаторе: {extra[0].upper()} {extra[1]}')
if len(ids)!=len(set(ids)): errors.append('Значения operationId должны быть уникальными')
# Инвариант P3: исторические маршрутизаторы физически удалены из канонического сервера.
config=(HTTP/'handler.go').read_text(encoding="utf-8")
if 'registerLegacy' in config or 'EnableLegacyAPI' in config: errors.append('В P3 необходимо удалить регистрацию устаревшего API')
if errors:
    print('Проверка контракта OpenAPI не пройдена:',file=sys.stderr)
    for e in errors: print(' - '+e,file=sys.stderr)
    raise SystemExit(1)
print(f'Контракт OpenAPI проверен: {len(code)} канонических операций, версия 1.0.0')

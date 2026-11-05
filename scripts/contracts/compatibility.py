#!/usr/bin/env python3
"""Завершаться с ошибкой при нарушающих совместимость изменениях относительно развёрнутой базовой
OpenAPI v1 версии 0.45.11.

Базовая версия содержит реальные опубликованные операции и схемы, а не список заявленных статусов.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'scripts/contracts/baselines/openapi-04511.json'
CURRENT = ROOT / 'schemas/openapi.yaml'
METHODS = {'get','post','put','patch','delete'}


def check(old, new):
    errors = []
    if old.get('info', {}).get('version') != new.get('info', {}).get('version'):
        errors.append('public OpenAPI contract version changed: major bump requires migration')
    for path, ops in old.get('paths', {}).items():
        for method, operation in ops.items():
            if method not in METHODS: continue
            current = new.get('paths', {}).get(path, {}).get(method)
            if current is None:
                errors.append(f'removed endpoint: {method.upper()} {path}')
                continue
            label = f'{method.upper()} {path}'
            if current.get('operationId') != operation.get('operationId'):
                errors.append(f'{label}: operationId changed')
            before_params = {(p.get('name'),p.get('in')):p for p in operation.get('parameters', [])}
            after_params = {(p.get('name'),p.get('in')):p for p in current.get('parameters', [])}
            for key, param in before_params.items():
                if key not in after_params or after_params[key].get('schema') != param.get('schema'):
                    errors.append(f'{label}: existing parameter changed: {key}')
            for key, param in after_params.items():
                if key not in before_params and param.get('required'):
                    errors.append(f'{label}: new required parameter: {key}')
            old_body = operation.get('requestBody') or {}
            new_body = current.get('requestBody') or {}
            if not old_body and new_body.get('required'):
                errors.append(f'{label}: newly required request body')
            if old_body and not new_body:
                errors.append(f'{label}: request body removed')
            for media, schema in old_body.get('content', {}).items():
                if new_body.get('content', {}).get(media, {}).get('schema') != schema.get('schema'):
                    errors.append(f'{label}: request schema/media changed: {media}')
            for status, response in operation.get('responses', {}).items():
                if status not in current.get('responses', {}):
                    errors.append(f'{label}: removed response status {status}')
                else:
                    old_media = response.get('content', {})
                    new_media = current['responses'][status].get('content', {})
                    for media, schema in old_media.items():
                        if media not in new_media or schema.get('schema') != new_media[media].get('schema'):
                            errors.append(f'{label}: changed response media/schema: {status} {media}')
    prev = old.get('components', {}).get('schemas', {})
    now = new.get('components', {}).get('schemas', {})
    for name, schema in prev.items():
        if name not in now or schema != now[name]:
            errors.append(f'public schema changed: {name} (requires compatibility review)')
    for name, response in old.get('components', {}).get('responses', {}).items():
        if new.get('components', {}).get('responses', {}).get(name) != response:
            errors.append(f'public response changed: {name}')
    return errors


def main():
    old = json.loads(BASE.read_text(encoding='utf-8'))
    new = json.loads(CURRENT.read_text(encoding='utf-8'))
    failures = check(old,new)
    if failures:
        for item in failures[:50]: print('BREAKING:', item, file=sys.stderr)
        raise SystemExit(f'{len(failures)} incompatible API changes vs 0.45.11')
    print('OpenAPI v1 backward compatibility PASS against 0.45.11:',
          sum(k in METHODS for ops in old['paths'].values() for k in ops))

if __name__ == '__main__': main()

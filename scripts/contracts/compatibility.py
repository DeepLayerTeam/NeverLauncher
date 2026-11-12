#!/usr/bin/env python3
"""Завершаться с ошибкой при нарушающих совместимость изменениях относительно развёрнутой базовой
OpenAPI v1 версии 0.45.11.

Базовая версия содержит реальные опубликованные операции и схемы, а не список заявленных статусов.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'scripts/contracts/baselines/openapi.json'
CURRENT = ROOT / 'schemas/openapi.yaml'
METHODS = {'get','post','put','patch','delete'}


def contract_shape(value):
    """Сравнивать машинные поля контракта, исключая переводимые описания документации."""
    if isinstance(value, dict):
        return {key: contract_shape(item) for key, item in value.items()
                if key not in ('description', 'summary', 'title')}
    if isinstance(value, list):
        return [contract_shape(item) for item in value]
    return value


def check(old, new):
    errors = []
    if old.get('info', {}).get('version') != new.get('info', {}).get('version'):
        errors.append('Версия публичного контракта OpenAPI изменилась: для повышения основной версии нужна миграция')
    for path, ops in old.get('paths', {}).items():
        for method, operation in ops.items():
            if method not in METHODS: continue
            current = new.get('paths', {}).get(path, {}).get(method)
            if current is None:
                errors.append(f'Удалён маршрут API: {method.upper()} {path}')
                continue
            label = f'{method.upper()} {path}'
            if current.get('operationId') != operation.get('operationId'):
                errors.append(f'{label}: изменён operationId')
            before_params = {(p.get('name'),p.get('in')):p for p in operation.get('parameters', [])}
            after_params = {(p.get('name'),p.get('in')):p for p in current.get('parameters', [])}
            for key, param in before_params.items():
                if key not in after_params or contract_shape(after_params[key].get('schema')) != contract_shape(param.get('schema')):
                    errors.append(f'{label}: изменён существующий параметр: {key}')
            for key, param in after_params.items():
                if key not in before_params and param.get('required'):
                    errors.append(f'{label}: новый обязательный параметр: {key}')
            old_body = operation.get('requestBody') or {}
            new_body = current.get('requestBody') or {}
            if not old_body and new_body.get('required'):
                errors.append(f'{label}: тело запроса стало обязательным')
            if old_body and not new_body:
                errors.append(f'{label}: тело запроса удалено')
            for media, schema in old_body.get('content', {}).items():
                if contract_shape(new_body.get('content', {}).get(media, {}).get('schema')) != contract_shape(schema.get('schema')):
                    errors.append(f'{label}: изменена схема или медиатип запроса: {media}')
            for status, response in operation.get('responses', {}).items():
                if status not in current.get('responses', {}):
                    errors.append(f'{label}: удалён статус ответа {status}')
                else:
                    old_media = response.get('content', {})
                    new_media = current['responses'][status].get('content', {})
                    for media, schema in old_media.items():
                        if media not in new_media or contract_shape(schema.get('schema')) != contract_shape(new_media[media].get('schema')):
                            errors.append(f'{label}: изменён медиатип или схема ответа: {status} {media}')
    prev = old.get('components', {}).get('schemas', {})
    now = new.get('components', {}).get('schemas', {})
    for name, schema in prev.items():
        if name not in now or contract_shape(schema) != contract_shape(now[name]):
            errors.append(f'Публичная схема изменилась: {name} (требуется проверка совместимости)')
    for name, response in old.get('components', {}).get('responses', {}).items():
        if contract_shape(new.get('components', {}).get('responses', {}).get(name)) != contract_shape(response):
            errors.append(f'Публичный ответ изменился: {name}')
    return errors


def main():
    old = json.loads(BASE.read_text(encoding='utf-8'))
    new = json.loads(CURRENT.read_text(encoding='utf-8'))
    failures = check(old,new)
    if failures:
        for item in failures[:50]: print('НАРУШЕНИЕ СОВМЕСТИМОСТИ:', item, file=sys.stderr)
        raise SystemExit(f'{len(failures)} Несовместимые изменения API относительно 0.45.11')
    print('Обратная совместимость OpenAPI v1 с 0.45.11 подтверждена:',
          sum(k in METHODS for ops in old['paths'].values() for k in ops))

if __name__ == '__main__': main()

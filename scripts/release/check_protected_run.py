#!/usr/bin/env python3
"""Требовать свежий завершённый защищённый workflow GitHub на точном коммите.

Проверяется по метаданным запуска GitHub API до использования независимо подписанных аттестаций
старого формата. Старые результаты workflow могут храниться в архиве, но не подтверждают новый
выпуск 0.36.2+ только из-за совпадения SHA исходников.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import re
import sys
from certification_run import required


def check(doc: dict, version: str, commit: str, workflow: str = '', *, now: datetime | None = None) -> None:
    if not isinstance(doc, dict) or doc.get('head_sha') != commit or doc.get('conclusion') != 'success' or doc.get('status') != 'completed':
        raise ValueError('Подтверждающие данные должны исходить из успешно выполненного процесса с точным совпадением коммита')
    if doc.get('event') != 'workflow_dispatch':
        raise ValueError('Требуется независимо запущенный оператором GA процесс workflow_dispatch')
    if workflow and not str(doc.get('path', '')).endswith('.github/workflows/'+workflow):
        raise ValueError('Неожиданный внешний процесс GA')
    if not required(version):
        return
    try:
        start = str(doc.get('run_started_at', ''))
        if not start.endswith('Z'):
            raise ValueError('Отсутствует время выполнения UTC')
        timestamp = datetime.fromisoformat(start.replace('Z', '+00:00'))
        attempt = doc.get('run_attempt')
        if type(attempt) is not int or attempt < 1:
            raise ValueError('Отсутствует номер попытки внешнего запуска GA')
        if type(doc.get('id')) is not int or doc['id'] < 1:
            raise ValueError('Недопустимый ID внешнего запуска GA')
    except (TypeError, ValueError) as exc:
        raise ValueError('У внешнего запуска GA отсутствуют достоверные метаданные') from exc
    current = now or datetime.now(timezone.utc)
    if not timedelta(0) <= current - timestamp <= timedelta(hours=24):
        raise ValueError('Внешний запуск GA устарел или просрочен (требуется повторный запуск)')


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--json',type=Path,required=True)
    p.add_argument('--version',required=True)
    p.add_argument('--commit',required=True)
    p.add_argument('--workflow',default='')
    a=p.parse_args()
    try:
        check(json.loads(a.json.read_text(encoding='utf-8')),a.version,a.commit,a.workflow)
    except (OSError,ValueError) as exc:
        print('ВНЕШНИЙ GA ЗАБЛОКИРОВАН: '+str(exc),file=sys.stderr)
        return 2
    print('Актуальный защищённый запуск GA принят (подпись и содержимое необходимо проверить отдельно)')
    return 0
if __name__=='__main__': sys.exit(main())

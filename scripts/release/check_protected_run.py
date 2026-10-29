#!/usr/bin/env python3
"""Require fresh, completed, exact-commit protected GitHub workflow execution.

Use on GitHub API run metadata before consuming independently signed old-format
attestations. Old workflow results may stay archived but cannot satisfy a new
0.36.2+ release invocation merely because their source SHA is the same.
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
        raise ValueError('protected evidence must originate from a successful exact-commit workflow')
    if doc.get('event') != 'workflow_dispatch':
        raise ValueError('independent GA operator workflow_dispatch is required')
    if workflow and not str(doc.get('path', '')).endswith('.github/workflows/'+workflow):
        raise ValueError('unexpected external GA workflow')
    if not required(version):
        return
    try:
        start = str(doc.get('run_started_at', ''))
        if not start.endswith('Z'):
            raise ValueError('missing UTC execution time')
        timestamp = datetime.fromisoformat(start.replace('Z', '+00:00'))
        attempt = doc.get('run_attempt')
        if type(attempt) is not int or attempt < 1:
            raise ValueError('missing external GA run attempt')
        if type(doc.get('id')) is not int or doc['id'] < 1:
            raise ValueError('invalid external GA run id')
    except (TypeError, ValueError) as exc:
        raise ValueError('external GA has no trustworthy run metadata') from exc
    current = now or datetime.now(timezone.utc)
    if not timedelta(0) <= current - timestamp <= timedelta(hours=24):
        raise ValueError('external GA execution is historical/expired (fresh rerun required)')


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
        print('EXTERNAL GA BLOCKED: '+str(exc),file=sys.stderr)
        return 2
    print('Fresh protected GA execution accepted (signature and contents must be verified separately)')
    return 0
if __name__=='__main__': sys.exit(main())

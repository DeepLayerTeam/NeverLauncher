#!/usr/bin/env python3
"""Reject incomplete, mislabeled or stale platform evidence for extension E2E."""
import argparse
import json
from pathlib import Path
import re
import sys

TARGETS = ('linux-x64', 'linux-arm64', 'windows-x64', 'windows-arm64',
           'macos-x64', 'macos-arm64')
CASES = ('java-host', 'java-runtime', 'java-lifecycle', 'gravit-port')


def validate(folder, source_commit):
    folder = Path(folder)
    present = {p.stem for p in folder.glob('*.json')}
    if present != set(TARGETS):
        raise ValueError(f'platform evidence missing or unexpected: {sorted(set(TARGETS) - present)} / {sorted(present - set(TARGETS))}')
    result = {}
    for name in TARGETS:
        report = json.loads((folder / f'{name}.json').read_text())
        if (report.get('target') != name or report.get('version') != '0.42.12'
                or report.get('status') != 'pass' or report.get('sourceCommit') != source_commit):
            raise ValueError(f'{name}: invalid status, version or source commit')
        checks = report.get('checks')
        if not isinstance(checks, dict) or set(checks) != set(CASES):
            raise ValueError(f'{name}: incomplete executable tests')
        for case, check in checks.items():
            if check.get('runtime') != 'pass' or not re.fullmatch('[0-9a-f]{64}', check.get('jarSha256', '')):
                raise ValueError(f'{name}/{case}: unverified JVM execution')
            if case in ('java-host', 'gravit-port'):
                signature = check.get('signing', {})
                if (not re.fullmatch('[0-9a-f]{64}', signature.get('sha256', ''))
                        or signature.get('wrongKeyDenied') is not True
                        or signature.get('tamperDenied') is not True):
                    raise ValueError(f'{name}/{case}: signed package negative tests absent')
        result[name] = {'status': 'pass', 'checks': len(checks)}
    return {'version': '0.42.12', 'sourceCommit': source_commit,
            'status': 'pass', 'platforms': result}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--evidence-dir', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        report = validate(args.evidence_dir, args.commit)
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f'extension E2E certification BLOCKED: {error}', file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print('PASS: six real JVM target results and signed-package negative checks')
    return 0


if __name__ == '__main__':
    sys.exit(main())

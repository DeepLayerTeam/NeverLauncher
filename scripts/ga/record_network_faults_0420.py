#!/usr/bin/env python3
"""Verify actual `go test -json -race` events for 0.42 host/JVM/fault tests.

This validator is not a replacement for Minecraft E2E. It verifies that every
required production-path Go test really passed, with no skips or test-run
failures, and binds the original Go output to its SHA-256 and source commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

REQUIRED = (
    'TestRemoteFaultUnknownBlocksNewAction04112',
    'TestRemoteFaultReadOnlyReceipt04112',
    'TestRemoteFaultCorruptJournalFailClosed04112',
    'TestRemoteFaultKernelSplitBrain04112',
    'TestRemoteFaultConcurrentUnknownDifferentKeys04112',
    'TestHostLifecycle0414RealJVMStartStopRestartAndSIGTERM',
    'TestHostLifecycle0414RealJVMAutoRecoveryAfterCrash',
    'TestHostLifecycle0414RealJVMCrashLoopIsBounded',
    'TestHostLifecycle0414ActualCLIAndRemoteEffects',
    'TestHostLifecycle0414StopWhileJavaCrashIsInBackoff',
    'TestWorldBackupCreateVerifyRestore02810',
    'TestWorldBackupGateBlocksStartAndSecondBackup04110',
    'TestWorldBackupGateFailsClosedAndRecoversOffline04110',
)
HEX_COMMIT = re.compile(r'^[a-f0-9]{40}$|^[a-f0-9]{64}$')


def network_gate_version(version: str) -> bool:
    """The 0.42.0 live gate stays mandatory for all subsequent product versions."""
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?', version)
    return match is not None and tuple(map(int, match.groups()[:3])) >= (0, 42, 0)


def validate(log: Path, commit: str, version: str) -> dict:
    if not HEX_COMMIT.fullmatch(commit) or not network_gate_version(version):
        raise ValueError('exact source commit and supported product version >= 0.42.0 required')
    if not log.is_file() or log.is_symlink() or not 0 < log.stat().st_size <= 64*1024*1024:
        raise ValueError('real go test JSON log missing/invalid')
    raw = log.read_bytes()
    seen: dict[str, str] = {}
    package_pass = False
    for line in raw.splitlines():
        row = json.loads(line)
        if type(row) is not dict or row.get('Package') != 'gitflic.ru/skif4er/neverlauncher/cli/cmd/neverlauncher':
            raise ValueError('incorrect Go test package/source')
        action = row.get('Action')
        test = row.get('Test')
        if action in ('fail', 'skip'):
            raise ValueError(f'Go test failed/skipped: {test or "package"}')
        if test in REQUIRED and action in ('pass', 'run'):
            if action == 'pass' and seen.get(test) == 'passed':
                raise ValueError(f'duplicate completed Go test: {test}')
            seen[test] = 'passed' if action == 'pass' else seen.get(test, 'running')
        if not test and action == 'pass':
            package_pass = True
    if not package_pass or any(seen.get(test) != 'passed' for test in REQUIRED):
        raise ValueError('required real JVM/RemoteControl/WorldBackup tests not all completed: '
                         + ', '.join(test for test in REQUIRED if seen.get(test) != 'passed'))
    return {'schemaVersion': 'neverlauncher.server-network.faults.0420/v1',
            'version': version, 'sourceCommit': commit, 'status': 'passed',
            'logFile': log.name, 'logSha256': hashlib.sha256(raw).hexdigest(),
            'tests': list(REQUIRED), 'raceDetector': True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.log, args.source_commit, args.version)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.exit(2, f'{args.version} HOST FAULT CERTIFICATION BLOCKED: {error}\n')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    temp = args.out.with_suffix('.json.tmp')
    temp.write_text(json.dumps(result, indent=2) + '\n')
    temp.replace(args.out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Exercise the *shipped* Linux x64 API from a signed release bundle.

Run AFTER final packaging/signing, and before publication. The external result
is an ordinary CI receipt, not a GA signature or a substitute for independent
platform certifications. Neither this runner nor its evidence changes the
signed bundle's bytes. A failed/absent test blocks release-bundle's CI job.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
RUNNER = HERE / 'minimal_live_e2e_0378.py'
BINARY = 'neverlauncher-api-linux-x64'
REQUIRED_CHECKS = frozenset((
    'installer_init', 'installer_diagnose', 'cold_start',
    'bootstrap_login_draft_and_stable_denial', 'active_writer_fencing_backup',
    'second_instance_rejected', 'sigterm_shutdown', 'graceful_restart',
    'graceful_state_verified', 'session_refresh_after_restart', 'sigkill_crash',
    'crash_recovery_start', 'durable_ack_survives_sigkill', 'stop_before_backup',
    'offline_consistent_backup_verify', 'verify_and_restore_clean_host',
    'restored_api_start', 'restored_auth_project_and_one_time_token',
    'restored_api_shutdown', 'corrupt_repository_prevents_api_start',
    'corruption_fail_closed',
))
SHA40 = re.compile(r'[0-9a-f]{40}\Z')
SHA64 = re.compile(r'[0-9a-f]{64}\Z')

class Blocked(ValueError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Blocked(message)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def identity(bundle: Path, version: str, commit: str) -> dict:
    require(bundle.is_dir() and not bundle.is_symlink(), 'invalid release bundle directory')
    require(SHA40.fullmatch(commit) is not None, 'invalid checkout SHA')
    require(version == (HERE.parents[1] / 'VERSION').read_text(encoding='utf-8').strip(),
            'requested version differs from checkout')
    manifest_path = bundle / 'RELEASE_MANIFEST.json'
    sums_path = bundle / 'SHA256SUMS'
    signature = bundle / 'SHA256SUMS.sig'
    for path in (manifest_path, sums_path, signature):
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                'missing/unsafe signed release metadata: ' + path.name)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    require(manifest.get('version') == version and manifest.get('sourceCommit') == commit,
            'manifest does not identify exact source/version')
    digests = {}
    for line in sums_path.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9][a-zA-Z0-9._+-]*)', line)
        require(match is not None, 'invalid SHA256SUMS entry')
        digest, name = match.groups()
        require(name not in digests, 'duplicate SHA256SUMS entry')
        digests[name] = digest
    require(BINARY in digests, 'final Linux API missing from signed asset list')
    binary = bundle / BINARY
    require(binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK),
            'final API artifact not executable')
    require(binary.stat().st_mode & 0o022 == 0, 'final API is group/world writable')
    digest = sha(binary)
    require(digest == digests[BINARY], 'final API SHA256 differs from signed checksums')
    return {'productVersion': version, 'sourceCommit': commit,
            'binarySha256': digest, 'sha256sumsSha256': sha(sums_path),
            'binary': str(binary.resolve())}


def validate_live_report(data: dict, expected: dict) -> None:
    require(data.get('schemaVersion') == 1 and data.get('status') == 'passed',
            'live E2E did not pass')
    require(all(data.get(key) == expected[key] for key in
                ('productVersion', 'sourceCommit', 'binarySha256')),
            'live E2E tested a different version/commit/binary')
    require(data.get('scope') == 'minimal-linux-real-process-no-ga-attestation',
            'wrong E2E execution scope')
    rows = data.get('checks')
    require(isinstance(rows, list) and len(rows) == len(REQUIRED_CHECKS) and
            all(isinstance(row, dict) and row.get('status') == 'passed' and
                isinstance(row.get('durationMs'), int) and row['durationMs'] >= 0 for row in rows),
            'missing/failed live execution steps')
    require({row['id'] for row in rows} == REQUIRED_CHECKS,
            'missing, duplicate or unexpected E2E step')


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', required=True, type=Path)
    p.add_argument('--version', required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--guard-policy', required=True, type=Path)
    p.add_argument('--bridge-policy', required=True, type=Path)
    p.add_argument('--work-root', required=True, type=Path)
    p.add_argument('--report', required=True, type=Path)
    args = p.parse_args(argv)
    result = {'schemaVersion': 1, 'status': 'blocked', 'productVersion': args.version,
              'sourceCommit': args.commit, 'scope': 'signed-final-bundle-minimal-live-e2e',
              'verifiedAt': datetime.now(timezone.utc).isoformat()}
    try:
        item = identity(args.bundle.absolute(), args.version, args.commit)
        result.update({k: v for k, v in item.items() if k != 'binary'})
        require(args.work_root.is_absolute() and args.work_root.is_dir() and
                not any(args.work_root.iterdir()), 'live E2E work root must be empty')
        live_path = args.report.with_name(args.report.stem + '-live.json')
        require(live_path != args.report, 'distinct report paths required')
        env = dict(os.environ, GITHUB_SHA=args.commit)
        proc = subprocess.run([sys.executable, str(RUNNER), '--binary', item['binary'],
              '--guard-policy', str(args.guard_policy), '--bridge-policy', str(args.bridge_policy),
              '--work-root', str(args.work_root), '--expected-version', args.version,
              '--report', str(live_path)], env=env, check=False)
        require(proc.returncode == 0, 'live E2E process failed')
        live = json.loads(live_path.read_text(encoding='utf-8'))
        validate_live_report(live, item)
        # Detect modification of the final asset between launch and signoff.
        require(identity(args.bundle.absolute(), args.version, args.commit) == item,
                'final artifact changed while E2E was running')
        result['liveReportSha256'] = sha(live_path)
        result['checksPassed'] = len(REQUIRED_CHECKS)
        result['status'] = 'passed'
    except (Blocked, OSError, ValueError, json.JSONDecodeError) as exc:
        result['failureType'] = type(exc).__name__
        print('FINAL BUNDLE E2E BLOCKED: ' + str(exc)[:250], file=sys.stderr)
    finally:
        # Report intentionally outside the already-signed release directory.
        args.report.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    return 0 if result['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())

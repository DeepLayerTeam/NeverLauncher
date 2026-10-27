#!/usr/bin/env python3
"""Fail-closed execution gate for NeverLauncher 0.32.16.

Runs real Go tests (including the live PostgreSQL, Redis and S3 paths) and
checks individual Go JSON test events. A clean process exit with skipped,
missing or unexecuted tests is NOT certification. Evidence is local and is
not a cryptographic attestation or permission to publish a GA release.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / 'services/api'
REQUIRED_ENV = (
    'NEVERLAUNCHER_SQLITE_TEST_ROOT', 'NEVERLAUNCHER_PG_TEST_DSN',
    'NEVERLAUNCHER_GROWTH_TEST_PG_DSN', 'NEVERLAUNCHER_GROWTH_TEST_REDIS_URL',
    'NEVERLAUNCHER_RC_S3_ENDPOINT', 'NEVERLAUNCHER_RC_S3_BUCKET',
    'NEVERLAUNCHER_RC_S3_REGION', 'NEVERLAUNCHER_RC_S3_ACCESS_KEY',
    'NEVERLAUNCHER_RC_S3_SECRET_KEY',
)

@dataclass(frozen=True)
class Suite:
    name: str
    package: str
    tests: tuple[str, ...]

SUITES = (
    Suite('auth-replay-mfa-and-minecraft', './internal/sqlitecore', (
        'TestAuthRotateReplayAndRestart', 'TestRefreshConcurrentReplayIsFailClosed',
        'TestSQLiteMFAEnrollmentRecoveryAndRevocation',
        'TestMinecraftCascadeRevokeUserAndStaleSession',
        'TestJoinAtomicRaceCrashRestartAndReplay', 'TestNodeNonceReplaySignatureAndTamper',
        'TestRevokedAuthenticationRejectsPendingTicket', 'TestReplayNonceRemainsSpentAfterReopen',
    )),
    Suite('jobs-lease-fencing-and-outbox', './internal/sqlitecore', (
        'TestDurableJobIdempotencyConcurrentLeaseAndCrash',
        'TestFencedCommitStaleEpochAfterReacquisition',
        'TestOutboxAtLeastOnceRestartAndIdempotentDelivery',
        'TestFullStateBridgeSignedRuntimeNoRedelivery',
        'TestFullStatePackagesSignaturesCASRestartAndRevocation',
    )),
    Suite('sqlite-real-crash-and-backup', './internal/sqlitedurable', (
        'TestAbruptExitRecovery', 'TestExclusiveOwner',
        'TestOnlineBackupWALAndVerifiedRestore', 'TestBackupTamperingAndOfflineLock',
    )),
    Suite('single-node-coordinator', './internal/sqlitecoord', (
        'TestRateLimitAtomicAndRestart', 'TestLeaseFencingAndRestart',
        'TestSingleOwnerAndChannel', 'TestLeaseExpiryFencingAndPrune',
        'TestProductionRCConcurrentRateLimitStress',
    )),
    Suite('postgres-transfer-invariants', './internal/sqlitepg', (
        'TestPGStagingMigration',
    )),
    Suite('actual-postgres-redis-and-s3', './internal/deployment', (
        'TestGrowthLivePostgresRedis03212',
        'TestProductionRCLiveS3Growth',
        'TestGrowthFailsClosedOnMissingPostgres03212',
        'TestExplicitModeRejectsUnsafeCombinations',
    )),
    Suite('http-security-and-minecraft', './internal/httpapi', (
        'TestSecurityRealAuthHTTP02912',
        'TestMinecraftAuth119NeverSessionExchangeJoinAndParentRevoke',
        'TestServerBridgeNodeIdentity0142RejectsSignatureReplayAndStaleTimestamp',
        'TestCanonicalStatusReadyAndMetrics',
    )),
    Suite('measured-load-safety', './cmd/neverlauncher-capacity-bench', (
        'TestMeasuredSuccessAndFailures',
        'TestProductionRCRejectsEveryUnexpectedResponse',
        'TestProductionRCMixedSuccessAndErrorsFails',
    )),
)

class GateError(RuntimeError):
    pass


def validate_events(lines: str, suite: Suite, returncode: int) -> dict:
    expected = set(suite.tests)
    finished: dict[str, str] = {}
    violations: list[str] = []
    for line in lines.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue  # Go may emit build diagnostics before JSON events
        if not isinstance(event, dict):
            continue
        test = event.get('Test')
        action = event.get('Action')
        if test and action in ('pass', 'fail', 'skip'):
            if action != 'pass':
                violations.append(f'{test}:{action}')
            if test in expected:
                if test in finished:
                    violations.append(f'{test}:duplicate result')
                finished[test] = action
        if not test and action == 'fail':
            violations.append('package:fail')
    missing = sorted(expected - finished.keys())
    wrong = sorted(k for k, v in finished.items() if v != 'pass')
    if returncode != 0 or missing or wrong or violations:
        raise GateError(f'{suite.name}: exit={returncode}, missing={missing}, not_passed={wrong}, problems={violations[:16]}')
    return {'suite': suite.name, 'package': suite.package, 'passed': sorted(expected), 'count': len(expected)}


def validate_preflight(env: dict[str, str]) -> str:
    missing = [k for k in REQUIRED_ENV if not env.get(k)]
    if missing:
        raise GateError('missing live dependencies: ' + ', '.join(missing))
    if env.get('NEVERLAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS') != '1':
        raise GateError('SQLite supported filesystem must be required, not skipped')
    root = Path(env['NEVERLAUNCHER_SQLITE_TEST_ROOT'])
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise GateError('SQLite test volume must be an existing absolute directory')
    if root.stat().st_mode & 0o077:
        raise GateError('SQLite test root must be private (0700)')
    return str(root.resolve())


def run_gate(output: Path, env: dict[str, str]) -> None:
    root = validate_preflight(env)
    if (ROOT / 'VERSION').read_text().strip() != '0.32.16':
        raise GateError('RC gate must run on canonical 0.32.16 sources')
    git_sha = env.get('GITHUB_SHA', '')
    if git_sha:
        git = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
        if git.returncode or git.stdout.strip() != git_sha:
            raise GateError('refusing CI evidence from an unexpected Git revision')
    version = subprocess.run(['go', 'version'], cwd=API, capture_output=True, text=True)
    if version.returncode or not re.search(r'go1\.(?:2[7-9]|[3-9]\d)\.', version.stdout):
        raise GateError('real Go 1.27+ toolchain required (no replacement dependencies)')
    env = dict(env)
    env['TMPDIR'] = root
    receipts = []
    for suite in SUITES:
        pattern = '^(' + '|'.join(map(re.escape, suite.tests)) + ')$'
        cmd = ['go', 'test', '-json', '-race', '-count=1', '-timeout=12m', '-run', pattern, suite.package]
        try:
            result = subprocess.run(cmd, cwd=API, env=env, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired as exc:
            raise GateError(f'{suite.name}: timed out') from exc
        receipts.append(validate_events(result.stdout, suite, result.returncode))
        print(f'{suite.name}: {receipts[-1]["count"]} real tests passed', flush=True)
    receipt = {
        'format': 'neverlauncher-03216-rc-test-evidence-v1',
        'version': '0.32.16', 'commit': git_sha or None,
        'sqlite_root': root, 'toolchain': version.stdout.strip(),
        'suites': receipts,
        'disclaimer': 'Tests are required but not proof of multi-host HA or complete product GA certification.',
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=output.parent, prefix='.rc-', delete=False) as f:
        staged = Path(f.name)
        os.chmod(staged, 0o600)
        json.dump(receipt, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(staged, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        run_gate(args.output, dict(os.environ))
    except (GateError, OSError) as exc:
        print(f'RC BLOCKED: {exc}', file=sys.stderr)
        return 2
    print('RC tests passed; remaining GA gates are still required.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

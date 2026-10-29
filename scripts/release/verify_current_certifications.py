#!/usr/bin/env python3
"""Fail closed on a reused, partial, skipped or stale active Admin/Profile GA receipt.

Receipt authenticity comes from the current GitHub Actions run artifacts and
restricted CI execution; this parser does not replace signed operator approval.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from certification_run import verify, CertificationBlocked

ROOT = Path(__file__).resolve().parents[2]
ADMIN_CHECKS = frozenset({
    'openapi', 'version', 'repository-policy', 'migration-parity', 'sdk-reproducibility',
    'admin-node-tests', 'vite-production-build', 'api-go-race', 'api-go-vet',
    'api-production-build', 'cli-go-race', 'cli-go-vet', 'cli-production-build',
    'postgresql-serverbridge-integration', 'live-playwright-rbac-two-tabs-recovery',
    'live-serverbridge-v3-save-drain-ack',
})
PROFILES = {
    'profile-v2-gravit-and-file-rules': frozenset((
        'TestProfileV2DeterministicSnapshots', 'TestFileOwnershipRules0224',
        'TestFileOwnershipSigningCompatibility0224', 'TestRuntimeConstraints0223RejectsUnsafeLaunch',
        'TestGravitImportReadyWorkspaceSettings02210', 'TestGravitImportFailClosed02210',
        'TestGravitImportDeterministicAndNoSourceSecrets02210',
    )),
    'workspace-and-channel-cas': frozenset((
        'TestGAWorkspaceImmutabilityAndStateMachine0230',
        'TestGAWorkspaceParallelRevisionCAS0230', 'TestGravitAtomicImportMemory02210',
        'TestGravitAtomicImportConcurrent02210', 'TestChannelHeadCASPublishAndRead0228',
        'TestGAWorkspacePostgresCASAndAtomicImport0230',
    )),
    'workspace-http-materialize': frozenset((
        'TestBuildWorkspaceDirectoryStageAndMaterialize0226',
        'TestGAHTTPGravitPreviewCommitAndConflict0230',
        'TestDesktopProfileServers0229ScopeAndPublicResponse',
    )),
    'client-update-and-repair': frozenset((
        'TestManifestUpdaterPreservesUserData0224', 'TestClientStateCASPreventsStaleUpdate0228',
        'TestTransactionalUpdaterPostVerifyFailureRollsBack0156',
        'TestTransactionalUpdaterCrashRecovery0156', 'TestClientLifecycleInstallRepairCleanupRollback',
    )),
}


def read(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2*1024*1024:
        raise CertificationBlocked('GA report missing, symlinked or oversized')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise CertificationBlocked('GA report must contain a JSON object')
    return data


def check_common(report: dict, version: str, commit: str):
    if (report.get('status') != 'passed' or report.get('productVersion') != version
            or report.get('commit') != commit):
        raise CertificationBlocked('GA certification status/version/commit mismatch')
    verify(report, version, commit)


def check_admin(report: dict, version: str, commit: str):
    check_common(report, version, commit)
    checks = report.get('checks')
    if not isinstance(checks, list) or len(checks) != len(ADMIN_CHECKS) or set(checks) != ADMIN_CHECKS:
        raise CertificationBlocked('Admin GA did not execute every mandatory live and build check')
    bundle = report.get('adminBundle')
    if not isinstance(bundle, dict) or 'index.html' not in bundle or len(bundle) < 2:
        raise CertificationBlocked('Admin GA has no production bundle')
    if any(not isinstance(p, str) or not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h)
           or p.startswith('/') or '..' in Path(p).parts for p, h in bundle.items()):
        raise CertificationBlocked('Admin GA bundle fingerprints malformed')
    if not re.fullmatch('[a-f0-9]{64}', str(report.get('openapiSha256', ''))):
        raise CertificationBlocked('Admin OpenAPI fingerprint missing')


def check_profiles(report: dict, version: str, commit: str):
    check_common(report, version, commit)
    suites = report.get('suites')
    if not isinstance(suites, list) or len(suites) != len(PROFILES):
        raise CertificationBlocked('profile GA must contain all real suites')
    found = set()
    for suite in suites:
        if not isinstance(suite, dict) or suite.get('status') != 'passed':
            raise CertificationBlocked('failed or malformed profile GA suite')
        key = suite.get('id')
        if key not in PROFILES or key in found:
            raise CertificationBlocked('unexpected or duplicate profile GA suite')
        found.add(key)
        tests = suite.get('tests')
        if not isinstance(tests, list) or len(tests) != len(PROFILES[key]) or set(tests) != PROFILES[key]:
            raise CertificationBlocked('profile GA suite skipped required real tests')
        command = suite.get('command')
        if not isinstance(command, list) or command[:5] != ['go','test','-json','-race','-count=1']:
            raise CertificationBlocked('profile GA suite did not record a real Go race-test command')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--admin', type=Path, required=True)
    p.add_argument('--profiles', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--version', required=True)
    a = p.parse_args()
    if (ROOT / 'VERSION').read_text().strip() != a.version:
        p.error('checkout version differs from requested version')
    try:
        check_admin(read(a.admin), a.version, a.commit)
        check_profiles(read(a.profiles), a.version, a.commit)
    except (OSError, ValueError, TypeError, KeyError) as e:
        print('ACTIVE GA BLOCKED: '+str(e), file=sys.stderr)
        return 2
    print('Active Admin/Profile GA passed: exact version, commit, run, attempt and real suites')
    return 0

if __name__ == '__main__':
    sys.exit(main())

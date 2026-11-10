#!/usr/bin/env python3
"""Блокировать повторно использованную, частичную, пропущенную или устаревшую квитанцию активной GA
Admin/Profile.

Подлинность квитанции устанавливается по артефактам текущего GitHub Actions и защищённому исполнению
CI; этот парсер не заменяет подписанное одобрение оператора.
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
        raise CertificationBlocked('Отчёт GA отсутствует, является символической ссылкой или превышает допустимый размер')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise CertificationBlocked('Отчёт GA должен содержать JSON-объект')
    return data


def check_common(report: dict, version: str, commit: str):
    if (report.get('status') != 'passed' or report.get('productVersion') != version
            or report.get('commit') != commit):
        raise CertificationBlocked('Несоответствие статуса, версии или коммита сертификации GA')
    verify(report, version, commit)


def check_admin(report: dict, version: str, commit: str):
    check_common(report, version, commit)
    checks = report.get('checks')
    required = ADMIN_CHECKS | ({'live-playwright-owner-cycle-0390'} if tuple(map(int, version.split('-', 1)[0].split('+', 1)[0].split('.')[:3])) >= (0,39,0) else set())
    if not isinstance(checks, list) or len(checks) != len(required) or set(checks) != required:
        raise CertificationBlocked('В Admin GA выполнены не все обязательные проверки рабочей среды и сборки')
    bundle = report.get('adminBundle')
    if not isinstance(bundle, dict) or 'index.html' not in bundle or len(bundle) < 2:
        raise CertificationBlocked('В Admin GA отсутствует производственный пакет')
    if any(not isinstance(p, str) or not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h)
           or p.startswith('/') or '..' in Path(p).parts for p, h in bundle.items()):
        raise CertificationBlocked('Отпечатки пакета Admin GA некорректны')
    if not re.fullmatch('[a-f0-9]{64}', str(report.get('openapiSha256', ''))):
        raise CertificationBlocked('Отсутствует отпечаток Admin OpenAPI')
    if tuple(map(int, version.split('-', 1)[0].split('+', 1)[0].split('.')[:3])) >= (0,39,0) and not re.fullmatch('[a-f0-9]{64}', str(report.get('ownerCycleReceiptSha256', ''))):
        raise CertificationBlocked('Отсутствует отпечаток квитанции реального браузерного E2E-теста владельца 0.39.0')


def check_profiles(report: dict, version: str, commit: str):
    check_common(report, version, commit)
    suites = report.get('suites')
    if not isinstance(suites, list) or len(suites) != len(PROFILES):
        raise CertificationBlocked('Приёмка профилей GA должна включать все реальные наборы тестов')
    found = set()
    for suite in suites:
        if not isinstance(suite, dict) or suite.get('status') != 'passed':
            raise CertificationBlocked('Набор тестов профилей GA не пройден или некорректен')
        key = suite.get('id')
        if key not in PROFILES or key in found:
            raise CertificationBlocked('Неожиданный или повторяющийся набор тестов профилей GA')
        found.add(key)
        tests = suite.get('tests')
        if not isinstance(tests, list) or len(tests) != len(PROFILES[key]) or set(tests) != PROFILES[key]:
            raise CertificationBlocked('В наборе тестов профилей GA пропущены обязательные реальные тесты')
        command = suite.get('command')
        if not isinstance(command, list) or command[:5] != ['go','test','-json','-race','-count=1']:
            raise CertificationBlocked('В наборе тестов профилей GA не зафиксирована реальная команда Go race-test')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--admin', type=Path, required=True)
    p.add_argument('--profiles', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--version', required=True)
    a = p.parse_args()
    if (ROOT / 'VERSION').read_text().strip() != a.version:
        p.error('Версия рабочей копии не соответствует запрошенной версии')
    try:
        check_admin(read(a.admin), a.version, a.commit)
        check_profiles(read(a.profiles), a.version, a.commit)
    except (OSError, ValueError, TypeError, KeyError) as e:
        print('ПРОВЕРКА ДЕЙСТВУЮЩЕЙ GA ЗАБЛОКИРОВАНА: '+str(e), file=sys.stderr)
        return 2
    print('Действующая GA для Admin и профилей пройдена: подтверждены точная версия, коммит, запуск, попытка и реальные тесты')
    return 0

if __name__ == '__main__':
    sys.exit(main())

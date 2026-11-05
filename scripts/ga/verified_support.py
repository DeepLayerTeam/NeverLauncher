#!/usr/bin/env python3
"""Вывести фактически поддерживаемые цели из независимой проверки GA по точным байтам.

Ни одно написанное вручную поле "supported" или запись манифеста выпуска не принимаются на веру.
Отчёт создаётся только после успешной проверки подписанного одобрения независимого оператора,
исходных трасс реальных запусков и всех шести финальных установщиков в verified_targets. Он
включается во внешне подписанный выпуск и повторно создаётся издателем.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from verified_targets import TARGETS, checks_for, verify
from security_capabilities_0431 import checks as security_checks, expected_scope

NAME = 'GA_VERIFIED_SUPPORT_0440.json'
SCHEMA = 'launcher.ga.verified-support.0440.v1'
# Известные ограничения — свойства модели безопасности продукта, а не необоснованное
# заявление о сертификации каждого аппаратно защищённого устройства.
BOUNDS = (
    'Device Trust and HWID are policy inputs; an HWID value is not hardware attestation.',
    'Native extension sandbox is verified per actual OS/architecture and policy; macOS single-process helper does not provide Windows Job or Linux cgroup subtree guarantees.',
    'TPM2 Certify/Quote is applicable only where supported physical TPM2 hardware and a verified platform implementation are available; this report does not claim universal hardware attestation.',
    'Client-side NeverGuard cannot guarantee resistance to an administrator who controls the host; server-side admission and revocation remain independent.',
    'Game compatibility is limited to the separately certified Minecraft/loader/OS combinations and component selections; it is not universal support for every modpack.',
)


def document(receipt: dict) -> dict:
    version = receipt['version']
    from release_policy import parsed
    if parsed(version)[0] < (0, 44, 0):
        raise ValueError('Требуется проверенный выпуск поддержки не ниже 0.44.0')
    if (receipt.get('status') != 'approved-for-release-signing'
            or receipt.get('schemaVersion') != 'launcher.ga.verified-targets.v2'
            or not isinstance(receipt.get('targets'), list)
            or len(receipt['targets']) != 6
            or {entry['target'] for entry in receipt['targets']} != set(TARGETS)):
        raise ValueError('Нельзя выпускать поддержку без шести сертифицированных целей с точным совпадением байтов')
    capabilities = list(security_checks(version))
    checked = list(checks_for(version))
    outputs = []
    for target in TARGETS:
        row = next(item for item in receipt['targets'] if item['target'] == target)
        if (row.get('checksPassed') != len(checked)
                or row.get('securityCapabilitiesVerified') != capabilities):
            raise ValueError(target + ': набор независимо проверенных возможностей неполон')
        outputs.append({
            'target': target,
            'binarySha256': row['binarySha256'],
            'packageSha256': row['packageSha256'],
            'checks': checked,
            'security': [
                {'capability': name, 'scope': expected_scope(name),
                 'verification': 'independent-operator-signature-and-native-observations'}
                for name in capabilities
            ],
        })
    return {
        'schemaVersion': SCHEMA, 'status': 'independently-verified-final-bytes',
        'version': version, 'commit': receipt['commit'],
        'approvalSha256': receipt['approvalSha256'],
        'operatorPublicKeySha256': receipt['operatorPublicKeySha256'],
        'supportBoundaries': list(BOUNDS), 'targets': outputs,
    }


def serialize(report: dict) -> bytes:
    return (json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def check_file(path: Path, receipt: dict) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Подписанный отчёт о проверенной поддержке отсутствует или небезопасен')
    if path.read_bytes() != serialize(document(receipt)):
        raise ValueError('Заявленная поддержка платформ расходится с результатом независимого повторного выполнения GA')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--trusted-key', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        receipt = verify(args.bundle, args.evidence, args.trusted_key, args.version, args.commit)
        args.output.write_bytes(serialize(document(receipt)))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        args.output.unlink(missing_ok=True)
        print('Выпуск проверенной поддержки 0.44.0 заблокирован: ' + str(exc), file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

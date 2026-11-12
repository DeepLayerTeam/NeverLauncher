#!/usr/bin/env python3
"""Продвижение Launcher 0.50.0 Gravit GA по проверенным финальным байтам выпуска.

Самоаттестация запрещена. Финальным подписантом должен быть *другой* независимый оператор; все
прежние живые проверки Migration GA и 19 настоящих тестов модулей должны быть повторены до принятия
внешне подписанного одобрения.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/gravit-port'))
sys.path.insert(0, str(ROOT / 'scripts/release'))
import ga_acceptance_0500 as ga
from delivery_verify_0462 import verify_bundle

DOMAIN = b'launcher.gravit.ga0500.independent.v1\x00'
VERSION = '0.50.0'
APPROVAL_SCHEMA = 'launcher.gravit.ga0500.independent.v1'


class Blocked(ValueError):
    pass


def require(value: bool, reason: str):
    if not value:
        raise Blocked(reason)


def verify_approval(evidence_root: Path, approval: Path, signature: Path, key: Path, acceptance: dict) -> dict:
    """Проверять отдельную подпись одобрения Ed25519 для каждого сохранённого файла и финального артефакта."""
    require(evidence_root.is_absolute() and evidence_root.is_dir() and not evidence_root.is_symlink(),
            'Требуется абсолютный путь к корневому каталогу реальных доказательств')
    raw = ga.regular(approval, 128 << 10, private=True)
    sig = ga.regular(signature, 128, private=True)
    key_raw = ga.regular(key, 128, private=True)
    require(len(sig) == 64 and len(key_raw) == 32, 'Требуются открытый ключ Ed25519 в исходном формате и подпись')
    try:
        Ed25519PublicKey.from_public_bytes(key_raw).verify(sig, DOMAIN + raw)
    except (InvalidSignature, ValueError) as exc:
        raise Blocked('Некорректная подпись независимой проверки') from exc
    try:
        meta = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise Blocked('Подтверждение не является корректным JSON') from exc
    require(type(meta) is dict and meta.get('schema') == APPROVAL_SCHEMA
            and meta.get('version') == VERSION and meta.get('commitSha') == acceptance['commitSha']
            and meta.get('targetReleaseSha256') == acceptance['targetReleaseSha256']
            and isinstance(meta.get('reviewer'), str) and 3 <= len(meta['reviewer']) <= 128,
            'Одобрение относится к другому выпуску или не указан проверяющий')
    files = meta.get('files')
    actual = {p.relative_to(evidence_root).as_posix() for p in evidence_root.rglob('*')
              if p.is_file() or p.is_symlink()}
    require(type(files) is dict and set(files) == actual
            and 'acceptance-0500.json' in files and
            all((module + '.evidence') in files for module in ga.MODULE_IDS)
            and any(name.startswith('signed/') for name in files),
            'Независимая подпись не охватывает все проверки модулей и подписанные файлы выпуска')
    for name, expected in files.items():
        require(type(name) is str and bool(re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', name))
                and not name.startswith('/') and '..' not in Path(name).parts
                and type(expected) is str and ga.HEX.fullmatch(expected) is not None,
                'Небезопасная опись подписанных доказательств')
        path = evidence_root / name
        require(path.resolve().is_relative_to(evidence_root.resolve()) and
                ga.sha(path) == expected, 'Подписанный файл доказательства отсутствует или изменён: ' + name)
    return meta


def promote(config: dict, evidence_root: Path, approval: Path, signature: Path, key: Path) -> dict:
    require((ROOT / 'VERSION').read_text().strip() == VERSION,
            'Версия исходников должна точно соответствовать итоговому выпуску 0.50.0')
    report = ga.doc(evidence_root / 'acceptance-0500.json', private=True)
    require(report.get('format') == ga.FORMAT and
            report.get('status') == 'LIVE_CHECKS_PASSED_REVIEW_REQUIRED' and
            report.get('productionGA') is False and report.get('migrationChecks') == 36 and
            report.get('moduleCheckCount') == 19 and
            type(report.get('references')) is list and len(report['references']) == 3 and
            type(report.get('moduleChecks')) is list and len(report['moduleChecks']) == 19,
            'Отсутствуют подтверждённые испытания реального проекта, 36 тестов миграции или 19 проверок модулей')
    try:
        completed = datetime.fromisoformat(report['completedAt'].replace('Z', '+00:00'))
    except (KeyError, AttributeError, ValueError) as exc:
        raise Blocked('В приёмке отсутствует дата') from exc
    now = datetime.now(timezone.utc)
    require(completed.tzinfo is not None and now - timedelta(hours=72) <= completed <= now + timedelta(minutes=1),
            'Доказательства приёмки устарели или имеют дату в будущем')
    classes = {x.get('referenceClass') for x in report['references'] if type(x) is dict}
    modules = {x.get('moduleId') for x in report['moduleChecks'] if type(x) is dict}
    require(classes == set(ga.CLASSES) and modules == set(ga.MODULE_IDS),
            'Неверный итоговый проект миграции или покрытие модулей')
    # Независимое подписанное одобрение должно покрывать РЕАЛЬНЫЕ финальные байты,
    # включая подписанный устанавливаемый выпуск и исходные незамаскированные
    # закрытые доказательства каждого модуля.
    signed_review = verify_approval(evidence_root, approval, signature, key, report)
    signed = evidence_root / 'signed'
    delivery = verify_bundle(signed, release_manifest=True)
    require(delivery.get('releaseManifestMatchesAssets') is True and delivery.get('version') == VERSION,
            'Подписанные артефакты поставки 0.50.0 не прошли реальные проверки манифеста или подписи')
    # Сравнивайте идентичность независимого проверяющего с авторами трёх подписанных
    # сертификатов Migration GA; самопроверка собственной квитанции GA запрещена.
    refs = config.get('references')
    require(type(refs) is dict and set(refs) == set(ga.CLASSES), 'Отсутствуют ссылки на реальный план и квитанции GA')
    for cls in ga.CLASSES:
        certificate = ga.doc(Path(refs[cls]['certificate']), private=True)
        require(signed_review['reviewer'] != certificate.get('reviewedBy'),
                'Независимый утверждающий не должен быть оператором исходной миграции')
    require(report['commitSha'] == signed_review['commitSha'],
            'Несовпадение коммита выпуска')
    # Повторно проверьте исходные 36 источников свидетельств и живой Backend после
    # внешней проверки. Откат или отзыв во время проверки блокирует окончательное
    # продвижение.
    ga.live_certificate_verification(config, refs)
    return {'version': VERSION, 'commitSha': report['commitSha'], 'targetReleaseSha256': report['targetReleaseSha256'],
            'independentlyApproved': True, 'signedDeliveryVerified': True,
            'liveMigrationChecks': 36, 'realModuleChecks': 19, 'threeProjects': True}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--approval', required=True, type=Path)
    parser.add_argument('--signature', required=True, type=Path)
    parser.add_argument('--trusted-reviewer-key', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = promote(ga.doc(args.config, private=True), args.evidence_root,
                         args.approval, args.signature, args.trusted_reviewer_key)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ga.Blocked, Blocked, OSError, KeyError, TypeError, RuntimeError, ValueError) as exc:
        print('Выпуск GRAVIT 0.50.0 для производства ЗАБЛОКИРОВАН: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

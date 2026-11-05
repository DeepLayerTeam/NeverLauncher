#!/usr/bin/env python3
"""Финальный допуск выпуска 0.48.0: независимо подписанная ЖИВАЯ приёмка и настоящая поставка.

Одна аттестация не превращает неудачную миграцию в успешную. Нужны все нативные артефакты, полная
живая приёмка владельца/хранилища/PG, настоящие исторические обновления и две реальные версии
клиента/сервера Mojang. Валидатор использует ВНЕШНИЕ результаты, не синтезирует свидетельства и не
обходит переключение SQLite.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
sys.path.insert(0, str(ROOT / 'scripts/integration'))
from delivery_verify_0462 import verify_bundle
import verify_0478
from check_protected_run import check as check_protected_run

DOMAIN = b'neverlauncher.ga0480.independent-operator.v1\x00'
VERSION = '0.48.0'
REQUIRED = {
    'live': 'live.json',
    'legacy': 'legacy.json',
    'owner': 'owner.json',
    'full_game': 'full-game/result.json',
    'matching_117': 'matching-1.17.1/result.json',
    'matching_121': 'matching-1.21.1/result.json',
    'staging_workflow': 'staging-workflow.json',
    'game_workflow': 'game-workflow.json',
    'delivery': 'signed/RELEASE_MANIFEST.json',
}

class GateError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise GateError(reason)


def read_safe(root: Path, name: str):
    require(isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9._/-]{1,240}', name) and '..' not in Path(name).parts and name.startswith(('signed/','full-game/','matching-1.17.1/','matching-1.21.1/')) or name in REQUIRED.values(), 'Неизвестный путь к доказательствам GA')
    p = root / name
    require(p.resolve().is_relative_to(root.resolve()) and p.is_file() and not p.is_symlink() and 0 < p.stat().st_size <= 8*1024*1024, f'Доказательства GA отсутствуют или небезопасны {name}')
    return p.read_bytes()


def report(root: Path, key: str):
    return json.loads(read_safe(root, REQUIRED[key]))


def validate_signed_attestation(root: Path, approval: Path, signature: Path, key: Path, commit: str):
    require(re.fullmatch('[a-f0-9]{40}', commit) is not None, 'Требуется точный коммит выпуска')
    raw = approval.read_bytes()
    require(len(raw) <= 128*1024 and raw and not approval.is_symlink(), 'Недопустимое содержимое подтверждения')
    sig = signature.read_bytes()
    key_raw = key.read_bytes()
    require(not key.is_symlink() and not signature.is_symlink() and len(sig) == 64 and len(key_raw) == 32, 'Требуются закреплённый ключ Ed25519 и отдельная подпись')
    try:
        Ed25519PublicKey.from_public_bytes(key_raw).verify(sig, DOMAIN + raw)
    except (ValueError, InvalidSignature) as exc:
        raise GateError('Независимая подпись оператора GA отклонена') from exc
    meta = json.loads(raw)
    require(meta.get('schema') == 'neverlauncher.ga0480.independent-operator.v1' and meta.get('version') == VERSION and meta.get('commit') == commit, 'Подтверждение оператора относится к другому выпуску или коммиту')
    files = meta.get('files')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    require(isinstance(files, dict) and set(REQUIRED.values()) <= set(files) and set(files) == actual, 'Независимое подписанное подтверждение должно охватывать каждый файл свидетельств и пакета')
    for name, expected in files.items():
        require(isinstance(expected, str) and re.fullmatch('[a-f0-9]{64}', expected) and hashlib.sha256(read_safe(root,name)).hexdigest() == expected, f'Байты независимой приёмки не совпадают: {name}')
    return meta


def inspect_live(root: Path):
    live = report(root,'live')
    require(live.get('schema') == 'neverlauncher.live-upgrade-acceptance-0480-v1' and live.get('version') == VERSION, 'Нет реальной независимой приёмки обновления')
    require(isinstance(live.get('sourceBaselineSHA256'), str) and re.fullmatch('[a-f0-9]{64}',live['sourceBaselineSHA256']), 'Отсутствует исходный контрольный SHA SQLite')
    require(isinstance(live.get('ownerId'), str) and bool(live['ownerId']) and isinstance(live.get('project'), str) and bool(live['project']), 'Не определены прежний владелец или проект')
    require(live.get('ownerLogin') == 'actual-session' and all(live.get(field) is True for field in ('apiEquivalent','sourceSQLiteVerified','storageVerified','cutoverVerified','backendPostgresVerified')), 'Не подтверждена работоспособность обновлённого Backend на PostgreSQL')


def gate(root: Path, approval: Path, signature: Path, key: Path, commit: str):
    require((ROOT / 'VERSION').read_text().strip() == VERSION, 'Исходный VERSION не равен 0.48.0')
    validate_signed_attestation(root,approval,signature,key,commit)
    inspect_live(root)
    verify_0478.legacy(root/REQUIRED['legacy'],VERSION)
    verify_0478.owner(root/REQUIRED['owner'],VERSION,commit)
    verify_0478.minecraft(root/'full-game',VERSION,mc='1.21.1')
    verify_0478.minecraft(root/'matching-1.17.1',VERSION,matching=True,mc='1.17.1')
    verify_0478.minecraft(root/'matching-1.21.1',VERSION,matching=True,mc='1.21.1')
    for name,workflow in (('staging_workflow','independent-migration-0480.yml'),('game_workflow','integration-matrix-0478.yml')):
        check_protected_run(report(root,name),VERSION,commit,workflow)
    delivery = verify_bundle(root/'signed',release_manifest=True)
    require(delivery.get('releaseManifestMatchesAssets') is True and delivery.get('version') == VERSION, 'Шесть подписанных пакетов выпуска не соответствуют описи поставки')
    return {'version':VERSION, 'commit':commit, 'signedDelivery':True, 'stagingUpgrade':True, 'legacyUpgrades':True, 'realMinecraft':True}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence-dir',type=Path,required=True)
    p.add_argument('--approval',type=Path,required=True)
    p.add_argument('--signature',type=Path,required=True)
    p.add_argument('--trusted-key',type=Path,required=True)
    p.add_argument('--commit',required=True)
    args=p.parse_args(argv)
    try:
        result=gate(args.evidence_dir,args.approval,args.signature,args.trusted_key,args.commit)
        print(json.dumps(result,sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, json.JSONDecodeError) as exc:
        print(f'Выпуск 0.48.0 заблокирован проверкой GA: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())

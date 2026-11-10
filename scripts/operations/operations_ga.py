#!/usr/bin/env python3
"""Подписать настоящую четырёхэтапную эксплуатационную приёмку подготовленного выпуска для шести платформ.

Запускать ТОЛЬКО после независимого выполнения обязательных установки, обновления, восстановления и
переключения при отказе на настоящих хостах. Утилита проверяет квитанции и читает финальные байты
пакетов. Проверка подписей и авторизация также выполняются Go-подписантом/валидатором; сама утилита
не присваивает статус выпуска.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import independent_accept_04514 as operational

ROOT = Path(__file__).resolve().parents[2]
# Стабильный домен подписи серии 0.46 и имена файлов доказательств. Версия подписана внутри
# документа; сохранение домена позволяет проверять исторический выпуск 0.46.0.
DOMAIN = b'neverlauncher.operations-ga.0460.v1\x00'
NAMES = ('install-standard', 'upgrade-standard', 'restore-standard', 'failover-network-ha')
SHA = re.compile(r'^[0-9a-f]{64}$')
COMMIT = re.compile(r'^[a-f0-9]{40}([a-f0-9]{24})?$')


def require(test, msg):
    if not test:
        raise ValueError(msg)


def fresh(timestamp: str, now: datetime):
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except (ValueError, AttributeError) as exc:
        raise ValueError('Некорректная временная метка приёмки') from exc
    require(dt.tzinfo is not None and now - timedelta(days=14) <= dt <= now + timedelta(minutes=5),
            'Время эксплуатационной приёмки истекло, находится в будущем или не содержит часового пояса')


def package_hash(path: Path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
            'Финальный установщик отсутствует или небезопасен: ' + path.name)
    return operational.sha(path)


def build_attestation(directory: Path, receipts: dict[str, Path], commit: str):
    version = (ROOT / 'VERSION').read_text().strip()
    require(COMMIT.fullmatch(commit) is not None, 'Некорректный коммит исходного кода')
    require(version in ('0.46.0', '0.46.1', '0.46.2', '0.46.3'), 'Неподдерживаемая версия эксплуатационной приёмки')
    records = {name: operational.read_receipt(path, name) for name, path in receipts.items()}
    args = argparse.Namespace(install_receipt=receipts[NAMES[0]], upgrade_receipt=receipts[NAMES[1]],
                              restore_receipt=receipts[NAMES[2]], failover_receipt=receipts[NAMES[3]])
    operational.accept_verify(args)
    now = datetime.now(timezone.utc)
    for name, data in records.items():
        require(data.get('status') == 'passed' and data.get('release') == version, 'Неверный выпуск на подготовительном этапе')
        fresh(data.get('completedUtc'), now)
        require(data.get('secondOperator') != data.get('firstOperator'), 'Оператор не является независимым')
    require(records['upgrade-standard'].get('identity', {}).get('oldAdminLogin') == 'verified' and
            records['upgrade-standard'].get('identity', {}).get('oldProjectRead') == 'verified',
            'Для обновления требуются проверенная реальная учётная запись и ранее созданный проект')
    require(records['restore-standard'].get('identity', {}).get('oldAdminLogin') == 'verified' and
            records['restore-standard'].get('identity', {}).get('oldProjectRead') == 'verified',
            'Для восстановления требуются проверенная реальная учётная запись и ранее созданный проект')
    require(records['failover-network-ha'].get('rpoSecondsObservedCanaries') == 0,
            'Все подтверждённые контрольные операции должны сохраниться после переключения при отказе')
    targets = {}
    for os_name, arch, filename in (
        ('windows', 'x64', f'launcher-desktop-{version}-windows-x64.zip'),
        ('windows', 'arm64', f'launcher-desktop-{version}-windows-arm64.zip'),
        ('linux', 'x64', f'launcher-linux-x64-{version}.tar.gz'),
        ('linux', 'arm64', f'launcher-linux-arm64-{version}.tar.gz'),
        ('darwin', 'x64', f'launcher-desktop-{version}-macos-x64.zip'),
        ('darwin', 'arm64', f'launcher-desktop-{version}-macos-arm64.zip')):
        targets[f'{os_name}-{arch}'] = {'name': filename, 'sha256': package_hash(directory / filename)}
    spec = ROOT / 'schemas/openapi.yaml'
    # Проверка v1 должна пройти до подписания оператором кандидата заморозки.
    import subprocess
    proc = subprocess.run([sys.executable, str(ROOT / 'scripts/contracts/compatibility_04512.py')],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    require(proc.returncode == 0, 'Проверка обратной совместимости OpenAPI v1 не пройдена')
    return {
        'schema': 'neverlauncher.operations-ga.0460.v1',
        'version': version, 'sourceCommit': commit, 'issuedAt': now.isoformat(),
        'operator': records[NAMES[0]]['secondOperator'],
        'sourceMachine': records['upgrade-standard']['machineFingerprint'],
        'restoreMachine': records['restore-standard']['machineFingerprint'],
        'stageReceipts': {name: operational.sha(receipts[name]) for name in NAMES},
        'openApiV1Sha256': operational.sha(spec),
        'targets': targets,
        'scope': 'Фактическая независимая эксплуатационная приёмка; оценён только RPO канареечного сценария, без утверждений об отказоустойчивости физических узлов и неизмеренном RPO нагрузки',
    }


def atomic_private(path: Path, content: bytes):
    operational.report_target(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(content); f.flush(); os.fsync(f.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def verify_public(bundle: Path, public_key_file: Path, release_key_file: Path):
    """Независимая проверка потребителя/издателя; закрытые отчёты не нужны.

    Намеренно отделена от поставляемого CLI, чтобы устаревший бинарный Launcher до 0.46 не мог
    разрешить неполный эксплуатационный выпуск.
    """
    require(bundle.is_dir() and not bundle.is_symlink(), 'Пакет выпуска отсутствует')
    require(public_key_file.resolve().is_relative_to(bundle.resolve()) is False,
            'Корень доверия оператора должен находиться вне пакета')
    require(release_key_file.resolve().is_relative_to(bundle.resolve()) is False,
            'Корень доверия выпуска должен находиться вне пакета')
    pub = serialization.load_pem_public_key(public_key_file.read_bytes())
    rel = serialization.load_pem_public_key(release_key_file.read_bytes())
    require(isinstance(pub, Ed25519PublicKey) and isinstance(rel, Ed25519PublicKey),
            'Оба корня доверия должны использовать Ed25519')
    key_bytes = lambda key: key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(key_bytes(pub) != key_bytes(rel), 'Подписант выпуска не может самостоятельно подтверждать собственные операции')
    def load(name, max_len):
        p = bundle / name
        require(p.is_file() and not p.is_symlink() and 0 < p.stat().st_size <= max_len,
                'Свидетельство выпуска отсутствует или небезопасно: '+name)
        return p.read_bytes()
    raw = load('OPERATIONS_GA_0460.json', 65536)
    import base64
    signature = base64.b64decode(load('OPERATIONS_GA_0460.sig', 1024).strip(), validate=True)
    require(len(signature) == 64, 'Некорректная длина подписи финальной эксплуатационной приёмки')
    try: pub.verify(signature, DOMAIN + raw)
    except InvalidSignature as exc: raise ValueError('Некорректная независимая подпись оператора') from exc
    document = json.loads(raw)
    manifest = json.loads(load('RELEASE_MANIFEST.json', 16*1024*1024))
    bom = json.loads(load('RELEASE_BOM.json', 16*1024*1024))
    require(document.get('schema') == 'neverlauncher.operations-ga.0460.v1' and
            document.get('version') == manifest.get('version') and
            document.get('sourceCommit') == manifest.get('sourceCommit') and
            COMMIT.fullmatch(document.get('sourceCommit','')),
            'Версия источника или коммит не совпадают')
    fresh(document.get('issuedAt'), datetime.now(timezone.utc))
    require(document.get('operator') and document.get('sourceMachine') != document.get('restoreMachine') and
            all(isinstance(document.get(name), str) and SHA.fullmatch(document[name]) for name in ('sourceMachine','restoreMachine','openApiV1Sha256')),
            'Некорректные независимо сертифицированные идентификаторы или контрольная сумма API')
    require(document.get('scope') == 'Фактическая независимая эксплуатационная приёмка; RPO проверен только на контрольных данных, без утверждений об отказоустойчивости физических узлов и неизмеренного RPO нагрузки',
            'Неподдерживаемая область эксплуатационных операций')
    stages = document.get('stageReceipts', {})
    require(isinstance(stages, dict) and set(stages) == set(NAMES) and
            all(isinstance(v, str) and SHA.fullmatch(v) for v in stages.values()),
            'Отсутствуют исходные контрольные суммы свидетельств операторской приёмки')
    apis = [c['sourceSha256'] for c in bom.get('components', []) if c.get('sourceFile') == 'schemas/openapi.yaml']
    require(apis == [document.get('openApiV1Sha256')], 'утверждённый API отличается от закреплённого источника в составе релиза')
    targets = document.get('targets')
    require(isinstance(targets, dict) and len(targets) == 6, 'Необходимо аттестовать шесть итоговых установщиков')
    for os_name, arch, filename in (
        ('windows','x64',f'launcher-desktop-{document["version"]}-windows-x64.zip'),
        ('windows','arm64',f'launcher-desktop-{document["version"]}-windows-arm64.zip'),
        ('linux','x64',f'launcher-linux-x64-{document["version"]}.tar.gz'),
        ('linux','arm64',f'launcher-linux-arm64-{document["version"]}.tar.gz'),
        ('darwin','x64',f'launcher-desktop-{document["version"]}-macos-x64.zip'),
        ('darwin','arm64',f'launcher-desktop-{document["version"]}-macos-arm64.zip')):
        target=targets.get(os_name+'-'+arch)
        require(isinstance(target,dict) and target.get('name') == filename and
                target.get('sha256') == package_hash(bundle/filename),
                'Поставленный пакет не получил независимого одобрения: '+filename)
    for name in ('OPERATIONS_GA_0460.json','OPERATIONS_GA_0460.sig'):
        require(name in manifest.get('requiredFiles', []) and any(
            f.get('name') == name and f.get('required') is True and f.get('status') == 'present' and
            f.get('sha256') == operational.sha(bundle/name) for f in manifest.get('artifacts',[])),
            'в подписанном манифесте выпуска отсутствует независимое утверждение: '+name)
    return {'status': 'verified', 'version': document['version'], 'commit': document['sourceCommit']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['attest', 'verify-public'])
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--source-commit')
    p.add_argument('--install-receipt', type=Path)
    p.add_argument('--upgrade-receipt', type=Path)
    p.add_argument('--restore-receipt', type=Path)
    p.add_argument('--failover-receipt', type=Path)
    p.add_argument('--operator-private-key', type=Path)
    p.add_argument('--output-dir', type=Path)
    p.add_argument('--trusted-operator-public-key', type=Path)
    p.add_argument('--release-public-key', type=Path)
    args = p.parse_args()
    try:
        if args.action == 'verify-public':
            require(args.trusted_operator_public_key and args.release_public_key,
                    'Требуются оба внешних открытых ключа')
            result = verify_public(args.bundle, args.trusted_operator_public_key, args.release_public_key)
            print(json.dumps(result))
            return 0
        require(all((args.source_commit, args.install_receipt, args.upgrade_receipt,
                     args.restore_receipt, args.failover_receipt, args.operator_private_key,
                     args.output_dir)), 'Отсутствуют входные данные аттестации')
        receipts = dict(zip(NAMES, (args.install_receipt, args.upgrade_receipt, args.restore_receipt, args.failover_receipt)))
        for file in receipts.values(): operational.private_file(file)
        key_path = operational.private_file(args.operator_private_key)
        require(key_path.stat().st_size < 16384, 'Ключ оператора превышает допустимый размер')
        private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        require(isinstance(private, Ed25519PrivateKey), 'Ключ оператора должен использовать Ed25519')
        require(args.output_dir.is_dir() and not args.output_dir.is_symlink() and
                not (args.output_dir.stat().st_mode & 0o077), 'Выходной каталог должен быть закрытым')
        approved = build_attestation(args.bundle, receipts, args.source_commit)
        primary = operational.read_receipt(receipts[NAMES[0]], NAMES[0])['firstOperator']
        require(operational.actor(primary) == approved['operator'],
                'Финальную подпись должен поставить второй независимый оператор, зарегистрированный в свидетельстве')
        raw = (json.dumps(approved, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
        sig = private.sign(DOMAIN + raw)
        import base64
        # Никогда не помещайте закрытый ключ, учётные данные или необработанные квитанции в
        # пакет выпуска.
        target = args.output_dir / 'OPERATIONS_GA_0460.json'
        atomic_private(target, raw)
        try:
            atomic_private(args.output_dir / 'OPERATIONS_GA_0460.sig', (base64.b64encode(sig).decode() + '\n').encode())
        except Exception:
            target.unlink(missing_ok=True)
            raise
        print('Эксплуатационная приёмка подписана; ещё необходимы итоговый выпуск и проверка нативных платформ')
    except (ValueError, OSError, operational.Rejected) as exc:
        print('ПРОВЕРКА GA ЗАБЛОКИРОВАНА: ' + str(exc), file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())

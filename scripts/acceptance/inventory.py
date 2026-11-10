#!/usr/bin/env python3
"""Приёмочная инвентаризация 0.52.1 с блокировкой при неопределённости и повторной проверкой независимо
подписанных свидетельств.

Запуск совместимости CI, собранный из исходников, НЕ является финальной проверкой нативных
пакетов/GA. Инвентаризация наблюдает исходные запуски Minecraft и оставляет каждую другую
обязательную цель в BLOCKED до её собственного независимо проверенного реального запуска. Подписание
— офлайн и только после полной повторной проверки свидетельств по 280 целям; даже подписанный обзор
не равен разрешению GA 0.53.0.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/compatibility'))
import matrix as compatibility

DOMAIN = b'neverlauncher.acceptance-inventory.0.52.1\x00'
SCHEMA = 'neverlauncher.acceptance-evidence/0.52.1'
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')
IDENTITY = re.compile(r'[A-Za-z][A-Za-z0-9._-]{2,63}\Z')
MAX_JSON = 8 * 1024 * 1024
MAX_LOG = 32 * 1024 * 1024
CATALOGS = {
    'minecraft': ('compatibility/targets.json', 280),
    'serverbridge': ('serverbridge/targets.json', 14),
    'device-trust': ('device-trust/targets.json', 7),
    'guard': ('guard-ci/targets.json', 3),
}
# Для каждой обязательной цели вне Minecraft назначен конкретный исполнитель.
RUNNERS = {
    'minecraft': 'e2e/scripts/run-compatibility-case.sh',
    'serverbridge': 'serverbridge/live_matrix_04113.py',
    'device-trust': 'scripts/device_trust/matrix.py',
    'guard': 'scripts/guard_ci/matrix.py',
}
E2E = tuple(f'E2E-{i:02d}' for i in range(1, 19))


class Blocked(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise Blocked(message)


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'Повторяющееся поле JSON: ' + key)
        out[key] = value
    return out


def safe_file(path: Path, limit: int):
    require(path.is_absolute() and not path.is_symlink() and path.is_file(),
            'Доказательство отсутствует, имеет относительный путь или символическую ссылку: ' + str(path))
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
            'Доказательство пусто, имеет жёсткую ссылку или превышает размер: ' + str(path))
    # Отклоняйте также символьные ссылки на родительские каталоги, включая распакованные архивы.
    require(not any(parent.is_symlink() for parent in path.parents),
            'Символическая ссылка в пути доказательства: ' + str(path))
    return path


def read_json(path: Path) -> dict:
    raw = safe_file(path, MAX_JSON).read_bytes()
    try:
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                         parse_constant=lambda token: (_ for _ in ()).throw(Blocked('Недопустимое нечисловое значение JSON')))
    except Blocked:
        raise
    except (UnicodeError, ValueError) as exc:
        raise Blocked('Некорректный JSON: ' + str(path)) from exc
    require(type(doc) is dict, 'Корневой элемент JSON должен быть объектом: ' + str(path))
    return doc


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(chunk)
    return sha.hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def catalogs():
    loaded = {}
    for group, (filename, minimum) in CATALOGS.items():
        path = ROOT / filename
        doc = read_json(path)
        require(doc.get('schemaVersion') == '1.0' and
                doc.get('productVersion', VERSION) == VERSION,
                group + ': несовпадение версии каталога или схемы')
        targets = doc.get('targets')
        require(type(targets) is list and len(targets) >= minimum,
                group + ': обязательная матрица сокращена')
        ids = set()
        for target in targets:
            require(type(target) is dict and type(target.get('required')) is bool and
                    isinstance(target.get('id'), str) and
                    compatibility.ID_RE.fullmatch(target['id']) is not None,
                    group + ': недопустимая цель матрицы')
            require(target['id'] not in ids, group + ': повторяющийся идентификатор цели')
            ids.add(target['id'])
        require(sum(row['required'] for row in targets) >= minimum,
                group + ': число обязательных целей стало меньше проверенной базовой конфигурации')
        require((ROOT / RUNNERS[group]).is_file(), group + ': отсутствует реальный исполняющий компонент')
        loaded[group] = {'rows': targets, 'sha256': digest(path), 'runner': RUNNERS[group]}
    # Повторно используйте существующую глубокую семантическую проверку загрузчика, Java и политики поддержки.
    compatibility.load_targets(ROOT / CATALOGS['minecraft'][0])
    return loaded


def locate_result_roots(results_root: Path):
    """Принимать только точные базовые имена экспортированных результатов; отклонять дублирующиеся ID и
небезопасные деревья."""
    if not results_root.exists():
        return {}, []
    require(results_root.is_absolute() and results_root.is_dir() and not results_root.is_symlink(),
            'Каталог результатов небезопасен')
    found, errors = {}, []
    for current, dirs, files in os.walk(results_root, followlinks=False):
        current_path = Path(current)
        for entry in dirs:
            require(not (current_path / entry).is_symlink(), 'Каталог подтверждающих данных является символической ссылкой')
        if 'compatibility-result.json' not in files:
            continue
        result_path = current_path / 'compatibility-result.json'
        doc = read_json(result_path)
        name = doc.get('targetId')
        require(isinstance(name, str) and compatibility.ID_RE.fullmatch(name),
                'Недопустимый targetId в доказательстве')
        require(name not in found, 'Повторяющаяся проверенная цель: ' + name)
        found[name] = (result_path, doc)
    return found, errors


def verify_runtime_bytes(target, result_path: Path):
    """Повторно проверять реальные результаты сертификации, а не только верхнеуровневое ``checks: true``."""
    runtime = (result_path.parent.parent / 'runtime' if result_path.parent.name == 'compatibility-result'
               else result_path.parent / 'runtime')
    base = read_json(runtime / 'result.json')
    require(base.get('status') == 'passed', target['id'] + ': проверка среды выполнения не пройдена')
    if target['scope'] == 'client':
        loader = target['loader']
        cert = read_json(runtime / (loader + '-certification.json'))
        install = read_json(runtime / (loader + '-install.json'))
        verify = read_json(runtime / 'materialized-client-verify.json')
        require(cert.get('status') == 'passed' and
                cert.get('requiredJavaMajor') == target['javaMajor'] and
                cert.get('detectedJavaMajor') == target['javaMajor'] and
                (cert.get('timedOut') is True or cert.get('success') is True) and
                type(cert.get('classpathEntries')) is int and cert['classpathEntries'] > 0 and
                install.get('status') == 'installed-and-verified' and
                install.get('minecraftVersion') == target['minecraft'] and
                verify.get('status') == 'valid' and
                isinstance(verify.get('verify'), dict) and verify['verify'].get('valid') is True,
                target['id'] + ': данные JVM, загрузчика или установки противоречат статусу PASS')
        if loader == 'vanilla':
            require(cert.get('minecraftVersion') == target['minecraft'],
                    target['id'] + ': неверная реальная сборка Minecraft')
        else:
            require(cert.get('minecraftVersion') == install.get('profileId') and
                    cert.get('mainClass') == install.get('mainClass') and
                    install.get('loader') == loader,
                    target['id'] + ': неверная идентификация окружения загрузчика')
        if not target.get('matchingServer'):
            live = read_json(runtime / 'live-join.json')
            witness = read_json(runtime / 'live-server-witness.json')
            ready = read_json(runtime / 'live-server-ready.json')
            stopped = read_json(runtime / 'live-server-stopped.json')
            server_log = safe_file(runtime / 'matching-server.log', MAX_LOG).read_bytes()
            cert_file = runtime / (loader + '-certification.json')
            require(live.get('schema') == 'neverlauncher.compatibility-live-join/0.52.4' and
                    live.get('status') == 'passed' and live.get('targetId') == target['id'] and
                    live.get('minecraftVersion') == target['minecraft'] and
                    live.get('loader') == loader and live.get('javaMajor') == target['javaMajor'] and
                    live.get('profileId') == cert.get('minecraftVersion') and
                    live.get('serverLogSha256') == hashlib.sha256(server_log).hexdigest() and
                    live.get('clientCertificationSha256') == digest(cert_file) and
                    live.get('witnessSha256') == digest(runtime / 'live-server-witness.json') and
                    live.get('serverStoppedSha256') == digest(runtime / 'live-server-stopped.json') and
                    stopped.get('schema') == 'neverlauncher.compatibility-server-stopped/0.52.4' and
                    stopped.get('stoppedAfterLiveWitness') is True and
                    stopped.get('serverLogSha256') == hashlib.sha256(server_log).hexdigest() and
                    stopped.get('serverPid') == ready.get('serverPid') and
                    all(live.get(k) is True for k in ('playerJoined', 'playerOnlineViaRcon', 'worldTicksAdvanced')) and
                    ready.get('targetId') == target['id'] and ready.get('port') == live.get('serverPort') and
                    ready.get('serverArtifactSha256') == live.get('serverArtifactSha256') and
                    witness.get('targetId') == target['id'] and witness.get('serverPid') == ready.get('serverPid') and
                    witness.get('serverArtifactSha256') == ready.get('serverArtifactSha256') and
                    witness.get('username') == 'NL_Cert_Client' and
                    witness.get('joinedFromServerLog') is True and witness.get('playerOnlineViaRcon') is True and
                    type(witness.get('tickBefore')) is int and type(witness.get('tickAfter')) is int and
                    witness['tickAfter'] > witness['tickBefore'] and
                    cert.get('matchingServer') == '127.0.0.1' and
                    cert.get('matchingServerPort') == live.get('serverPort') and
                    re.search(rb'(?im)\bNL_Cert_Client\b.*(?:joined the game|logged in with entity id)', server_log),
                    target['id'] + ': доказательство реального многопользовательского входа недопустимо или изменено')
        if target.get('matchingServer'):
            match = read_json(runtime / 'matching-server.json')
            require(match.get('status') == 'passed' and match.get('clientJoinedServer') is True,
                    target['id'] + ': отсутствует подтверждённый реальный вход на соответствующий сервер')
    else:
        launch = read_json(runtime / 'runtime-launch-minecraft.json')
        require(base.get('mode') == 'compatibility' and
                (launch.get('success') is True or launch.get('timedOut') is True),
                target['id'] + ': не обнаружена реальная среда исполнения полного стека JVM')
    return runtime


def verify_compatibility(target, record, commit, run_id, attempt):
    path, doc = record
    require(doc.get('productVersion') == VERSION and doc.get('runAttempt') == attempt,
            target['id'] + ': несовпадение версии продукта или попытки CI')
    problems = compatibility.verify_result(target, doc, commit=commit, run_id=run_id)
    problems += compatibility.verify_evidence_files(path, doc)
    require(not problems, target['id'] + ': ' + '; '.join(problems[:5]))
    runtime_dir = verify_runtime_bytes(target, path)
    if target['scope'] == 'client' and not target.get('matchingServer'):
        live = read_json(runtime_dir / 'live-join.json')
        for receipt in ('live-server-ready.json', 'live-server-witness.json', 'live-server-stopped.json'):
            binding = read_json(runtime_dir / receipt)
            require(binding.get('sourceCommit') == commit and
                    binding.get('ciRunId') == run_id and
                    binding.get('ciRunAttempt') == attempt,
                    target['id'] + ': наблюдение сервера относится к другому запуску или попытке CI')
        require(live.get('sourceCommit') == commit and live.get('ciRunId') == run_id and
                live.get('ciRunAttempt') == attempt,
                target['id'] + ': данные многопользовательской игры относятся к другому запуску или попытке CI')
    raw = doc.get('evidence', {})
    hashes = raw.get('sha256') or {}
    require('compatibility-execution.log' in (raw.get('files') or []) and
            SHA.fullmatch(hashes.get('compatibility-execution.log', '')) is not None,
            target['id'] + ': отсутствует настоящий журнал выполнения с хешем')
    log = safe_file(path.parent / 'compatibility-execution.log', MAX_LOG).read_bytes()
    require(b'\x00' not in log and len(log) >= 32 and
            b'[compat]' in log and b'actual' in log.lower(),
            target['id'] + ': отсутствует содержательный журнал выполнения реального клиента')
    # Журналы могут содержать сведения учётных записей; никогда не публикуйте bearer-токены авторизации.
    require(not re.search(rb'(?i)(authorization:\s*bearer\s+\S+|refresh[_ -]?token\s*[=:]\s*\S+)', log),
            target['id'] + ': в журнале выполнения обнаружены незамаскированные учётные данные')
    require(digest(path.parent / 'compatibility-execution.log') == hashes['compatibility-execution.log'],
            target['id'] + ': журнал выполнения изменён')
    return {
        'targetId': target['id'], 'status': 'observed',
        'resultSha256': digest(path), 'logSha256': hashes['compatibility-execution.log'],
        'files': {name: hashes[name] for name in sorted(hashes)},
        'source': 'real-compatibility-run-not-final-installer',
    }


def inventory(results_root: Path, commit: str, run_id: str, attempt: int, *, strict=False):
    require(COMMIT.fullmatch(commit) is not None and RUN.fullmatch(run_id) is not None and
            type(attempt) is int and attempt > 0, 'Требуются настоящий коммит Git, идентификатор запуска и номер попытки')
    tables = catalogs()
    found, errors = locate_result_roots(results_root)
    required = {t['id']: t for t in tables['minecraft']['rows'] if t['required']}
    require(not (set(found) - set(required)), 'Неизвестные или необязательные цели подтверждения: ' +
            ', '.join(sorted(set(found) - set(required))[:6]))
    rows = []
    for group in CATALOGS:
        for target in tables[group]['rows']:
            if not target['required']:
                rows.append({'id': group + '/' + target['id'], 'required': False,
                             'status': 'optional-unverified', 'runner': tables[group]['runner']})
                continue
            name = target['id']
            item = {'id': group + '/' + name, 'required': True,
                    'runner': tables[group]['runner'], 'status': 'blocked'}
            if group == 'minecraft' and name in found:
                try:
                    item['evidence'] = verify_compatibility(target, found[name], commit, run_id, attempt)
                    item['status'] = 'observed'
                except (Blocked, OSError, KeyError, TypeError, ValueError) as exc:
                    item['error'] = str(exc)[:512]
            elif group != 'minecraft':
                item['reason'] = 'Требуется независимо проверенное подтверждение запуска для соответствующего набора'
            else:
                item['reason'] = 'Отсутствуют подтверждения фактического запуска клиента'
            rows.append(item)
    for e2e in E2E:
        rows.append({'id': 'user/' + e2e, 'required': True, 'status': 'blocked',
                     'reason': 'Требуются отдельные приёмки реального пользовательского сценария и итогового пакета'})
    counts = {'required': sum(x['required'] for x in rows),
              'observed': sum(x['status'] == 'observed' for x in rows),
              'blocked': sum(x['status'] == 'blocked' for x in rows),
              'optional': sum(not x['required'] for x in rows)}
    result = {'schema': SCHEMA, 'version': VERSION, 'commit': commit, 'runId': run_id,
              'runAttempt': attempt, 'catalogSha256': {k: v['sha256'] for k, v in tables.items()},
              'scope': 'CI-source-observation-not-final-package-GA',
              'status': 'BLOCKED' if counts['blocked'] else 'OBSERVED_NOT_GA',
              'counts': counts, 'targets': rows}
    if strict:
        need = [t for t in rows if t['id'].startswith('minecraft/') and t['required']]
        require(all(t['status'] == 'observed' for t in need),
                f'Неполные доказательства Minecraft: {sum(t["status"] == "observed" for t in need)}/{len(need)}')
    return result


def public_key(path: Path, pinned_sha: str):
    require(SHA.fullmatch(pinned_sha) is not None, 'Требуется независимо закреплённый SHA-256 открытого ключа')
    key = serialization.load_pem_public_key(safe_file(path, 8192).read_bytes())
    require(isinstance(key, Ed25519PublicKey), 'Допустимы только открытые ключи независимых проверяющих Ed25519')
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(hashlib.sha256(der).hexdigest() == pinned_sha, 'Ключ проверяющего не совпадает с независимо закреплённым ключом')
    return key


def write_exclusive(path: Path, data: bytes):
    require(path.is_absolute() and not path.exists() and not path.is_symlink(),
            'Требуется новый абсолютный путь вывода')
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'Небезопасный каталог вывода')
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def signed_payload(args):
    receipt = inventory(args.results_root.resolve(), args.commit, args.run_id, args.attempt, strict=True)
    require(IDENTITY.fullmatch(args.reviewer) is not None, 'Требуется указать личность проверяющего')
    return {'schema': SCHEMA + '/review', 'reviewer': args.reviewer, 'reviewType': 'independent-observation-not-GA',
            'observation': receipt}


def command_inventory(args):
    result = inventory(args.results_root.resolve(), args.commit, args.run_id, args.attempt)
    content = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.output:
        write_exclusive(args.output.resolve(), content.encode('utf-8'))
    else:
        print(content)
    if args.gate == 'minecraft':
        expected = sum(t['required'] for t in result['targets'] if t['id'].startswith('minecraft/'))
        checked = sum(t['status'] == 'observed' for t in result['targets'] if t['id'].startswith('minecraft/'))
        return 0 if checked == expected else 3
    return 0 if result['counts']['blocked'] == 0 else 3


def command_sign(args):
    require(args.private_key.resolve().is_relative_to(ROOT) is False,
            'Закрытый ключ независимой подписи должен храниться вне рабочей копии исходников')
    require(args.private_key.stat().st_mode & 0o077 == 0, 'Закрытый ключ подписанта должен иметь права 0600')
    pinned = public_key(args.public_key.resolve(), args.public_key_sha256)
    key = serialization.load_pem_private_key(safe_file(args.private_key.resolve(), 8192).read_bytes(), password=None)
    require(isinstance(key, Ed25519PrivateKey) and key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw) == pinned.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        'Закрытый и открытый ключи проверяющего не совпадают')
    payload = signed_payload(args)
    raw = DOMAIN + canonical(payload)
    envelope = {'payload': payload, 'signatureEd25519': key.sign(raw).hex(),
                'publicKeySha256': args.public_key_sha256}
    write_exclusive(args.output.resolve(), canonical(envelope) + b'\n')
    print('Независимые свидетельства CI подписаны (это НЕ окончательный нативный пакет и не GA): ' + str(args.output))
    return 0


def command_verify(args):
    key = public_key(args.public_key.resolve(), args.public_key_sha256)
    sealed = read_json(args.receipt.resolve())
    require(set(sealed) == {'payload', 'signatureEd25519', 'publicKeySha256'} and
            sealed['publicKeySha256'] == args.public_key_sha256 and
            isinstance(sealed['signatureEd25519'], str) and
            re.fullmatch(r'[0-9a-f]{128}', sealed['signatureEd25519']) is not None,
            'Некорректная оболочка подписи или неверный ключ подписи')
    try:
        key.verify(bytes.fromhex(sealed['signatureEd25519']), DOMAIN + canonical(sealed['payload']))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise Blocked('Независимая проверка подписи завершилась ошибкой') from exc
    require(sealed['payload'] == signed_payload(args),
            'Подписанные доказательства отличаются от повторно проверенных наблюдений или актуальных каталогов')
    print('ПРОЙДЕНО: повторно проверены подписанные результаты CI для 280 целей; GA остаётся заблокированной')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('inventory', 'sign', 'verify'):
        p = sub.add_parser(command)
        p.add_argument('--results-root', type=Path, required=True)
        p.add_argument('--commit', required=True)
        p.add_argument('--run-id', required=True)
        p.add_argument('--attempt', type=int, required=True)
        if command == 'inventory':
            p.add_argument('--output', type=Path)
            p.add_argument('--gate', choices=('full', 'minecraft'), default='full')
        else:
            p.add_argument('--reviewer', required=True)
            p.add_argument('--public-key', type=Path, required=True)
            p.add_argument('--public-key-sha256', required=True)
            if command == 'sign':
                p.add_argument('--private-key', type=Path, required=True)
                p.add_argument('--output', type=Path, required=True)
            else:
                p.add_argument('--receipt', type=Path, required=True)
        p.set_defaults(action=globals()['command_' + command])
    args = parser.parse_args()
    try:
        return args.action(args)
    except (Blocked, OSError, TypeError, KeyError, ValueError) as exc:
        print('Приёмка заблокирована: ' + str(exc), file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Итоговая приёмочная проверка финальных байтов. Повторно проверяет настоящие свидетельства, никогда
не превращая CI в GA.

`minecraft` запускает все 280 глубоких проверок по сырым результатам целевых раннеров. `full`
дополнительно повторно проверяет шесть финальных нативных установок, шесть настоящих запусков GUI на
нативных системах, шесть независимо подписанных пересборок, пять часовых игровых прогонов и час
реальной HTTPS-нагрузки. Нужно отдельное независимое разрешение GA.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/acceptance'))
sys.path.insert(0, str(ROOT / 'scripts/release'))
sys.path.insert(0, str(ROOT / 'scripts/ga'))
import inventory_0521 as inventory
import native_packages_0522 as native
import independent_current_05211 as reproducible
import verify_six_native_game_0440 as native_game

SHA = re.compile(r'[a-f0-9]{64}\Z')
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')
SOAK_TARGETS = {
 'vanilla-26.3-linux-x64': 'vanilla',
 'fabric-26.3-linux-x64': 'fabric',
 'quilt-26.3-linux-x64': 'quilt',
 'forge-26.3-linux-x64': 'forge',
 'neoforge-26.2-linux-x64': 'neoforge',
}

class Blocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Blocked(why)

def read_json(path: Path, limit=16*1024*1024):
    inventory.safe_file(path, limit)
    return inventory.read_json(path)

def verify_minecraft(root, commit, run_id, attempt):
    report = inventory.inventory(root, commit, run_id, attempt, strict=True)
    entries = [row for row in report['targets'] if row['id'].startswith('minecraft/') and row['required']]
    require(len(entries) == 280 and all(e['status'] == 'observed' for e in entries),
            'Проверены не все 280 реальных целей Minecraft')
    return {'status': '280_REAL_CI_OBSERVATIONS_NOT_GA', 'targets': len(entries),
            'catalogSha256': report['catalogSha256']['minecraft'],
            'sha256': hashlib.sha256(inventory.canonical(report)).hexdigest()}

def signed_soak(root: Path, pubkey: Path, pin: str, commit: str, run_id: str, attempt: int, kind: str):
    summary = read_json(root / 'soak.json', 8*1024*1024)
    sig = inventory.safe_file(root / 'soak.sig', 128).read_bytes()
    require(len(sig) == 64 and SHA.fullmatch(pin or '') is not None, 'Требуется подписанная квитанция нагрузочного прогона и закреплённый ключ')
    key = inventory.public_key(pubkey, pin)
    try:
        key.verify(sig, ('neverlauncher.soak.real.' + inventory.VERSION + '\x00').encode() + inventory.canonical(summary))
    except InvalidSignature as exc:
        raise Blocked('Некорректная независимая подпись свидетельства длительного тестирования') from exc
    return raw_soak(root, commit, run_id, attempt, kind)

def raw_soak(root: Path, commit: str, run_id: str, attempt: int, kind: str):
    summary = read_json(root / 'soak.json', 8*1024*1024)
    require(summary.get('schema') == 'neverlauncher.real-soak/' + inventory.VERSION and
            summary.get('status') == 'OBSERVED_NOT_GA' and
            summary.get('version') == inventory.VERSION == '0.53.0' and
            summary.get('commit') == commit and summary.get('runId') == run_id and
            summary.get('attempt') == attempt and summary.get('mode') == kind and
            type(summary.get('seconds')) in (float,int) and summary['seconds'] >= 3600,
            'Недопустимая область, идентификатор или длительность длительного нагрузочного прогона')
    if kind == 'game':
        target_id = summary.get('target')
        require(target_id in SOAK_TARGETS, 'Длительная игровая проверка не охватывает пять обязательных загрузчиков')
        targets = {t['id']:t for t in inventory.catalogs()['minecraft']['rows'] if t['required']}
        sessions = summary.get('sessions')
        require(type(sessions) is list and 8 <= len(sessions) <= 200, 'Отсутствуют реальные сеансы')
        actual = sorted(p.name for p in root.glob('session-*'))
        require(actual == [f'session-{i+1:03d}' for i in range(len(sessions))],
                'Доказательства длительного игрового прогона отсутствуют или повторяются')
        duration = 0
        for i, (sample, receipt) in enumerate(zip(actual,sessions),1):
            require(receipt.get('session') == i and type(receipt.get('seconds')) in (int,float)
                    and receipt['seconds'] > 0, 'Некорректные данные сеанса или времени')
            duration += receipt['seconds']
            sample_dir = root / sample
            log = inventory.safe_file(sample_dir / 'runner.log',32*1024*1024)
            require(inventory.digest(log) == receipt.get('runnerLogSha256'), 'Журнал длительного нагрузочного прогона изменён')
            path = sample_dir / 'compatibility-result/compatibility-result.json'
            raw = read_json(path)
            verified = inventory.verify_compatibility(targets[target_id], (path,raw), commit, run_id, attempt)
            require(verified['resultSha256'] == receipt.get('resultSha256') and
                    verified['files'].get('matching-server.log') == receipt.get('serverLogSha256'),
                    'Данные длительного прогона получены не из реальной игровой сессии')
        require(duration >= 0.5 * summary['seconds'], 'Недостаточная продолжительность реальных сеансов')
        return {'targetId': target_id,'sessions':len(sessions),'seconds':summary['seconds'],
                'receiptSha256': inventory.digest(root/'soak.json')}
    # Повторно воспроизводите сырые измерения вместо принятия независимо подписанного, но
    # основанного только на заявлении p95/status. По 20 байт на реальный TLS-запрос.
    ledger = inventory.safe_file(root/'requests.bin', 210*1024*1024)
    require(inventory.digest(ledger) == summary.get('requestsSha256'),
            'Журнал HTTPS-запросов изменён или отсутствует')
    require(ledger.stat().st_size % 20 == 0 and
            ledger.stat().st_size // 20 == summary.get('requests'),
            'Неполные или обрезанные измерения HTTPS-запросов')
    times, durations, total_bytes = [], [], 0
    with ledger.open('rb') as stream:
        while part := stream.read(20):
            require(len(part) == 20, 'Неполная выборка запросов')
            when, elapsed, size = struct.unpack('!QdI', part)
            require(0 < elapsed <= 30000 and 0 < size <= 256*1024 and
                    (not times or times[-1] <= when), 'Неупорядоченное по времени или недопустимое измерение TLS')
            times.append(when); durations.append(elapsed); total_bytes += size
    require(len(times) >= 10000 and times[-1]-times[0] >= 3590*10**9,
            'Временные метки запросов не охватывают полный реальный час')
    import math
    p95 = sorted(durations)[math.ceil(.95*len(durations))-1]
    require(round(p95,3) == summary.get('p95Ms') and
            total_bytes == summary.get('responseBytes'),
            'Независимый пересчёт не совпадает с заявленными задержками или объёмом')
    require(type(summary.get('requests')) is int and summary['requests'] >= 10000 and
            summary.get('failed') == 0 and summary.get('concurrency',0) >= 1 and
            type(summary.get('p95Ms')) in (int,float) and 0 <= summary['p95Ms'] <= 1500,
            'Длительная проверка HTTPS не достигла минимальной нагрузки')
    return {'requests': summary['requests'], 'p95Ms': summary['p95Ms'],
            'seconds':summary['seconds'],'receiptSha256':inventory.digest(root/'soak.json')}

def verify_repro(a):
    ka,kb = a.repro_a_key, a.repro_b_key
    require(ka.read_bytes()!=kb.read_bytes(), 'Независимые сборщики должны использовать разные ключи')
    reproducible.pinned_key(ka,a.repro_a_pin)
    reproducible.pinned_key(kb,a.repro_b_pin)
    doc_a = reproducible.signed_json(a.repro_a_report,a.repro_a_sig,ka)
    doc_b = reproducible.signed_json(a.repro_b_report,a.repro_b_sig,kb)
    report = reproducible.compare(doc_a,doc_b,a.repro_a_dir,a.repro_b_dir,
                                  a.commit,a.repro_run_id,a.repro_attempt)
    return {'sha256':hashlib.sha256(inventory.canonical(report)).hexdigest(),
            'targets': {name:row['sha256'] for name,row in report['targets'].items()},
            'builders':report['builders']}

def verify_full(a):
    require(COMMIT.fullmatch(a.commit or '') is not None and inventory.VERSION == '0.53.0',
            'Требуются точный актуальный коммит исходников и версия 0.53.0')
    report = {'schema':'neverlauncher.full-compatibility-sweep/' + inventory.VERSION,
              'version':inventory.VERSION,'commit':a.commit,'status':'BLOCKED'}
    report['minecraft'] = verify_minecraft(a.compat_results,a.commit,a.compat_run_id,a.compat_attempt)
    native_args = SimpleNamespace(results=a.native_results,source_index=a.source_index,
       manifest_sha256=a.index_sha,version=inventory.VERSION,commit=a.commit,project=a.project,
       run_id=a.native_run_id,attempt=str(a.native_attempt),public_key=a.native_key,
       public_key_sha256=a.native_key_pin,receipt=a.native_review,reviewer=a.native_reviewer)
    native.verify_review(native_args)  # Подпись и повторная проверка всех шести журналов установки.
    report['nativePackages'] = native.aggregate(native_args)
    report['nativeGame'] = native_game.verify(a.native_game_results,a.package_id,
          inventory.VERSION,a.commit,a.native_game_run_id)
    report['reproducibility'] = verify_repro(a)
    require(a.game_soaks.is_dir() and not a.game_soaks.is_symlink(),
            'Отсутствует реальный каталог длительной игровой проверки, рассмотренный независимым проверяющим')
    directory_names = {entry.name for entry in a.game_soaks.iterdir()}
    require(directory_names == set(SOAK_TARGETS) or
            directory_names == set(SOAK_TARGETS) | {'https'},
            'Необходимы пять отдельных каталогов длительных проверок загрузчиков без посторонних элементов')
    for name in sorted(SOAK_TARGETS):
        folder = a.game_soaks / name
        require(folder.is_dir() and not folder.is_symlink(), 'Небезопасный каталог длительной игровой проверки')
        row = signed_soak(folder,a.soak_key,a.soak_key_pin,a.commit,a.soak_run_id,
                          a.soak_attempt,'game')
        require(row['targetId'] == name, 'Неверно обозначен каталог длительной проверки загрузчика')
        report.setdefault('gameSoaks',[]).append(row)
    report['httpSoak'] = signed_soak(a.http_soak,a.soak_key,a.soak_key_pin,
                                    a.commit,a.soak_run_id,a.soak_attempt,'https')
    report['status'] = 'OBSERVED_NOT_INDEPENDENT_GA'
    return report

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='mode',required=True)
    for mode in ('minecraft','full'):
        s = sub.add_parser(mode)
        s.add_argument('--commit', required=True)
        s.add_argument('--compat-results', required=True, type=Path)
        s.add_argument('--compat-run-id', required=True)
        s.add_argument('--compat-attempt', required=True, type=int)
        s.add_argument('--output', required=True, type=Path)
        if mode == 'full':
            for name in ('native-results','source-index','native-review','native-key',
                         'native-game-results','repro-a-report','repro-b-report','repro-a-sig',
                         'repro-b-sig','repro-a-key','repro-b-key','repro-a-dir','repro-b-dir',
                         'game-soaks','http-soak','soak-key'):
                s.add_argument('--'+name, required=True, type=Path)
            for name in ('index-sha','project','native-run-id','native-key-pin',
                         'native-reviewer','native-game-run-id','package-id',
                         'repro-run-id','repro-a-pin','repro-b-pin','soak-run-id','soak-key-pin'):
                s.add_argument('--'+name, required=True)
            for name in ('native-attempt','repro-attempt','soak-attempt'):
                s.add_argument('--'+name,type=int,required=True)
    a = p.parse_args()
    try:
        require(COMMIT.fullmatch(a.commit or '') is not None and RUN.fullmatch(a.compat_run_id or '') is not None,
                'Требуются корректные точные данные исходников и запуска CI')
        if a.mode == 'full':
            doc = verify_full(a)
        else:
            doc = {'schema':'neverlauncher.full-compatibility-sweep/' + inventory.VERSION,
                   'version':inventory.VERSION,'commit':a.commit,
                   'status':'280_REAL_CI_OBSERVATIONS_NOT_GA',
                   'minecraft':verify_minecraft(a.compat_results,a.commit,a.compat_run_id,a.compat_attempt)}
        require(a.output.is_absolute() and not a.output.exists(), 'Требуется новое абсолютное имя файла отчёта')
        inventory.write_exclusive(a.output,(json.dumps(doc,sort_keys=True,indent=2)+'\n').encode())
        print('PASS: реальные наблюдения воспроизведены; независимая итоговая GA остаётся заблокированной')
        return 0
    except (Blocked, inventory.Blocked, native.Blocked, reproducible.Blocked, OSError,
            ValueError, TypeError, KeyError, InvalidSignature) as exc:
        print('Полная проверка совместимости заблокирована: '+str(exc),file=sys.stderr)
        return 3

if __name__ == '__main__':
    raise SystemExit(main())

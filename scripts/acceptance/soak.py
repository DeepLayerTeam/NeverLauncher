#!/usr/bin/env python3
"""Настоящие длительные сеансы Minecraft и нагрузка управляющего HTTPS, без синтетического PASS.

`game` многократно выполняет имеющийся полный E2E Mojang/загрузчика/сервера; исходные результаты по
каждому прогону повторно проверяются inventory_0521 до архивации. `http` посылает реальные
параллельные аутентифицированные TLS-запросы в одноразовую лабораторию Standard/HA; недоступная или
ограничивающая запросы служба не проходит порог. Оба режима фиксируют реальное и монотонное время, а
также исходные хешированные свидетельства. Не является квитанцией GA.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import http.client as http_client

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/acceptance'))
sys.path.insert(0, str(ROOT / 'scripts/compatibility'))
import inventory_0521 as inventory

SCHEMA = 'neverlauncher.real-soak/' + inventory.VERSION
MAX_LOG = 32 * 1024 * 1024
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')

class Blocked(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise Blocked(message)

def digest(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for buf in iter(lambda: f.read(1024*1024), b''):
            h.update(buf)
    return h.hexdigest()

def output_dir(path: Path):
    require(path.is_absolute() and not path.exists() and not path.is_symlink(),
            'Требуется новый абсолютный путь каталога отчётов')
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'Небезопасный родительский каталог')
    path.mkdir(mode=0o700)
    return path

def write_receipt(path: Path, data):
    raw = (json.dumps(data, indent=2, sort_keys=True, allow_nan=False)+'\n').encode()
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush(); os.fsync(handle.fileno())

def check_identity(args):
    require(COMMIT.fullmatch(args.commit or '') is not None and RUN.fullmatch(args.run_id or '') is not None
            and type(args.attempt) is int and args.attempt > 0, 'Требуются действительные идентификаторы коммита CI и запуска')
    require(inventory.VERSION >= '0.53.0', 'Требуется версия продукта 0.53.0 или новее')
    require(3600 <= args.min_seconds <= 24*3600, 'Нагрузочная проверка должна выполняться не менее одного реального часа')

def copy_selected(raw: Path, destination: Path, names):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(len(names) == len(set(names)) and len(names) <= 100, 'Небезопасный список файлов подтверждения')
    for name in names:
        require(isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}',name),
                'untrusted evidence basename')
        source = raw / name
        inventory.safe_file(source, MAX_LOG)
        shutil.copyfile(source, destination / name)

def session_archive(target, destination: Path, args):
    result_dir = ROOT / 'e2e/compatibility-result'
    result = inventory.read_json(result_dir / 'compatibility-result.json')
    verified = inventory.verify_compatibility(target, (result_dir / 'compatibility-result.json', result),
                                               args.commit, args.run_id, args.attempt)
    ev = result['evidence']['files']
    # Сохраняйте первоначальные сырые результаты и свидетельства журналов с хешами, а не один JSON PASS.
    copy_selected(result_dir, destination / 'compatibility-result',
                  ['compatibility-result.json'] + [x for x in ev if x in
                    ('java-runtime.json','platform-runtime.json','compatibility-execution.log')])
    runtime_src = ROOT / 'e2e/runtime'
    runtime_names = [x for x in ev if x not in
                     ('java-runtime.json','platform-runtime.json','compatibility-execution.log')]
    # Совместимость охватывает файлы вне подписанного списка, только если они явно нужны глубокому
    # верификатору. Сохраняйте их и повторно проверяйте скопированное дерево.
    for name in ('result.json', f"{target['loader']}-install.json",
                 f"{target['loader']}-certification.json", 'materialized-client-verify.json',
                 'live-join.json', 'live-server-ready.json','live-server-witness.json',
                 'live-server-stopped.json', 'matching-server.log','matching-server.json',
                 'runtime-launch-minecraft.json'):
        if (runtime_src / name).is_file() and name not in runtime_names:
            runtime_names.append(name)
    copy_selected(runtime_src, destination / 'runtime', runtime_names)
    copied = inventory.read_json(destination / 'compatibility-result/compatibility-result.json')
    require(inventory.verify_compatibility(
        target, (destination / 'compatibility-result/compatibility-result.json', copied),
        args.commit, args.run_id, args.attempt) == verified,
        'Скопированное свидетельство сессии Minecraft не соответствует исходному реальному запуску')
    return verified

def run_game_subprocess(log, env, timeout):
    """По тайм-ауту завершать всю группу подпроцессов Minecraft/сервера."""
    with log.open('xb') as handle:
        child = subprocess.Popen(['bash', 'e2e/scripts/run-compatibility-case.sh'],
                                 cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=30)
            raise Blocked('Превышено время ожидания игрового E2E-сеанса Minecraft; группа процессов завершена')
        finally:
            handle.flush()
            os.fsync(handle.fileno())

def game(args):
    check_identity(args)
    require(args.min_sessions >= 8 and args.min_sessions <= 200, 'Требуется не менее восьми реальных клиент-серверных сеансов')
    targets = {t['id']: t for t in inventory.catalogs()['minecraft']['rows'] if t['required']}
    require(args.target_id in targets and targets[args.target_id]['scope'] == 'client',
            'Необходимо выбрать обязательную целевую конфигурацию реального клиента Minecraft')
    target = targets[args.target_id]
    env = os.environ.copy()
    expected = {'LAUNCHER_COMPAT_TARGET_ID': target['id'], 'LAUNCHER_COMPAT_OS': target['os'],
                'LAUNCHER_COMPAT_ARCH': target['arch'], 'LAUNCHER_COMPAT_SCOPE': target['scope'],
                'LAUNCHER_E2E_MINECRAFT_VERSION': target['minecraft'],
                'LAUNCHER_E2E_LOADER': target['loader'],
                'LAUNCHER_E2E_LOADER_VERSION': target['loaderVersion'],
                'LAUNCHER_E2E_JAVA_MAJOR': str(target['javaMajor']),
                'LAUNCHER_COMPAT_MATCHING_SERVER': str(target.get('matchingServer',False)).lower(),
                'GITHUB_SHA': args.commit, 'GITHUB_RUN_ID': args.run_id,
                'GITHUB_RUN_ATTEMPT': str(args.attempt)}
    require(env.get('LAUNCHER_ACCEPTANCE_DISPOSABLE') == '1',
            'длительный игровой тест может очищать e2e/runtime только в разрешённой временной рабочей копии')
    require(env.get('LAUNCHER_E2E_JAVA'), 'Необходимо явно выбрать существующую поддерживаемую JRE')
    for key, value in expected.items():
        require(not env.get(key) or env[key] == value, 'Конфликт метаданных исполняющего компонента: ' + key)
    env.update(expected)
    out = output_dir(args.output)
    started = time.monotonic()
    receipt = {'schema': SCHEMA, 'mode': 'game', 'status': 'BLOCKED',
               'version': inventory.VERSION, 'commit': args.commit, 'runId': args.run_id,
               'attempt': args.attempt, 'target': target['id'], 'startedAt': datetime.now(timezone.utc).isoformat(),
               'sessions': []}
    try:
        while time.monotonic()-started < args.min_seconds or len(receipt['sessions']) < args.min_sessions:
            i = len(receipt['sessions'])
            require(i < args.max_sessions, 'Лимит сеансов достигнут раньше минимальной продолжительности')
            sample = out / f'session-{i+1:03d}'
            sample.mkdir(mode=0o700)
            # Не используйте устаревшие результаты прежней попытки игры или runner.
            for folder in ('e2e/compatibility-result', 'e2e/runtime'):
                old = ROOT / folder
                require(not old.is_symlink(), 'Небезопасное повторное использование каталога среды выполнения')
                if old.is_dir():
                    shutil.rmtree(old)
            start = time.monotonic()
            log = sample / 'runner.log'
            rc = run_game_subprocess(log, env, args.session_timeout)
            require(log.stat().st_size <= MAX_LOG, 'Размер игрового журнала превышает лимит')
            require(not re.search(rb'(?i)(authorization:\s*bearer\s+\S+|refresh[_ -]?token\s*[=:]\s*\S+)',
                                  log.read_bytes()), 'unredacted secrets in game runner output')
            require(rc == 0, f'Реальные клиент/сервер завершились ошибкой (сеанс {i+1}): {rc}')
            verified = session_archive(target, sample, args)
            receipt['sessions'].append({'session': i+1, 'seconds': round(time.monotonic()-start,3),
                                        'resultSha256': verified['resultSha256'],
                                        'serverLogSha256': verified['files'].get('matching-server.log'),
                                        'runnerLogSha256': digest(log)})
        duration = time.monotonic()-started
        require(duration >= args.min_seconds and len(receipt['sessions']) >= args.min_sessions,
                'Недостаточная длительность реального выполнения')
        receipt['seconds'] = round(duration,3)
        receipt['status'] = 'OBSERVED_NOT_GA'
        write_receipt(out/'soak.json', receipt)
        return 0
    except BaseException:
        receipt['seconds'] = round(time.monotonic()-started,3)
        write_receipt(out/'blocked.json', receipt)
        raise

def check_https(url):
    u = urllib.parse.urlsplit(url)
    require(u.scheme == 'https' and u.hostname and u.username is None and u.password is None
            and not u.fragment and u.port != 0 and len(url) <= 2048, 'допускается только конечная точка HTTPS')
    return u

def https_once(url: str, timeout: float):
    u = check_https(url)
    connection = http_client.HTTPSConnection(u.hostname, u.port or 443,
                                             timeout=timeout, context=ssl.create_default_context())
    begin = time.monotonic()
    try:
        connection.request('GET', (u.path or '/') + (('?' + u.query) if u.query else ''),
                           headers={'Accept': 'application/json', 'Cache-Control': 'no-store'})
        response = connection.getresponse()
        data = response.read(256 * 1024 + 1)
        require(response.status == 200 and 0 < len(data) <= 256*1024,
                'Ошибка Backend (статус HTTP, пустой или слишком большой ответ)')
        return (time.monotonic()-begin)*1000, len(data)
    finally:
        connection.close()

def percentile(values, q):
    require(len(values) >= 2, 'Недостаточно наблюдений нагрузки')
    values = sorted(values)
    return values[min(len(values)-1, int(len(values)*q + .999999)-1)]

def http(args):
    check_identity(args)
    check_https(args.url)
    require(1 <= args.concurrency <= 64 and 1000 <= args.min_requests <= 10_000_000 and
            1 <= args.max_p95_ms <= 30000, 'Неподдерживаемый бюджет нагрузки')
    out = output_dir(args.output)
    started = time.monotonic()
    durations, bytes_total, failures = [], 0, 0
    report = {'schema': SCHEMA, 'mode': 'https', 'status': 'BLOCKED',
              'version': inventory.VERSION, 'commit': args.commit, 'runId': args.run_id,
              'attempt': args.attempt, 'concurrency': args.concurrency,
              'startedAt': datetime.now(timezone.utc).isoformat()}
    try:
        with (out/'requests.bin').open('xb') as ledger, ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            pending = set()
            while time.monotonic()-started < args.min_seconds or len(durations) < args.min_requests:
                for _ in range(max(0, args.concurrency-len(pending))):
                    pending.add(pool.submit(https_once, args.url, args.timeout))
                done, pending = wait(pending, timeout=args.timeout+1, return_when=FIRST_COMPLETED)
                require(done, 'Обработчики HTTP-запросов перестали отвечать')
                for future in done:
                    try:
                        elapsed, size = future.result()
                        durations.append(elapsed); bytes_total += size
                        ledger.write(struct.pack('!QdI', time.monotonic_ns(), elapsed, size))
                    except Exception:
                        failures += 1
                require(failures == 0, 'Ошибка запроса под нагрузкой HTTPS')
                require(len(durations) <= 10_000_000, 'Превышен лимит данных подтверждения запросов')
                require(time.monotonic()-started < args.max_seconds, 'Нагрузочная проверка превысила утверждённое время')
            for task in pending:
                task.cancel()
            ledger.flush(); os.fsync(ledger.fileno())
        span = time.monotonic()-started
        p95 = percentile(durations,.95)
        require(span >= args.min_seconds and len(durations) >= args.min_requests and
                p95 <= args.max_p95_ms, 'Не достигнуты целевые значения задержки, объёма или длительности нагрузки')
        report.update({'status': 'OBSERVED_NOT_GA', 'seconds': round(span,3),
                       'requests': len(durations), 'failed': failures, 'responseBytes': bytes_total,
                       'p50Ms': round(percentile(durations,.5),3), 'p95Ms': round(p95,3),
                       'p99Ms': round(percentile(durations,.99),3),
                       'requestsPerSecond': round(len(durations)/span,3),
                       'requestsSha256': digest(out/'requests.bin')})
        write_receipt(out/'soak.json', report)
        return 0
    except BaseException:
        report.update({'seconds': round(time.monotonic()-started,3),
                       'requests': len(durations), 'failed': failures})
        write_receipt(out/'blocked.json', report)
        raise

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='mode', required=True)
    for mode in ('game', 'http'):
        s = sub.add_parser(mode)
        s.add_argument('--commit', required=True)
        s.add_argument('--run-id', required=True)
        s.add_argument('--attempt', type=int, required=True)
        s.add_argument('--min-seconds', type=int, default=3600)
        s.add_argument('--output', type=Path, required=True)
        if mode == 'game':
            s.add_argument('--target-id', required=True)
            s.add_argument('--min-sessions', type=int, default=8)
            s.add_argument('--max-sessions', type=int, default=100)
            s.add_argument('--session-timeout', type=int, default=1200)
        else:
            s.add_argument('--url', required=True)
            s.add_argument('--concurrency', type=int, default=8)
            s.add_argument('--min-requests', type=int, default=10000)
            s.add_argument('--max-seconds', type=int, default=9000)
            s.add_argument('--max-p95-ms', type=int, default=1500)
            s.add_argument('--timeout', type=float, default=15)
        s.set_defaults(action=game if mode=='game' else http)
    a = p.parse_args()
    try:
        return a.action(a)
    except (Blocked, OSError, ValueError, subprocess.TimeoutExpired, AssertionError,
            json.JSONDecodeError) as exc:
        print('Длительная проверка в реальной среде заблокирована: '+str(exc), file=sys.stderr)
        return 3

if __name__ == '__main__':
    raise SystemExit(main())

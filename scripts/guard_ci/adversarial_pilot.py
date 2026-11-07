#!/usr/bin/env python3
"""Выполнить настоящие регрессионные проверки Guard; проверить подписанные серверные наблюдения и
реальные игровые свидетельства.

Никакой синтетической сертификации: при отсутствии ПО, живых игроков, настоящих артефактов
Minecraft, рассмотренных инцидентов или измеренных кадров игры результат BLOCKED, а не PASS.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
HEX = re.compile(r'^[0-9a-f]{64}$')
BOOT = re.compile(r'^[0-9a-f]{32}$')
SAFE = re.compile(r'^[a-z][a-z0-9_:-]{0,95}$')
SUITES = (
    ('loader-transformations', 'scripts/tests/guard_loader_0504.py', 6),
    ('runtime-integrity', 'scripts/tests/guard_runtime_integrity_0505.py', 7),
    ('continuous-watchdog', 'scripts/tests/continuous_game_protection_0506.py', 2),
    ('linux-process-protection', 'scripts/tests/linux_runtime_guard_0508.py', 4),
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    with path.open('rb') as handle:
        sha = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            sha.update(chunk)
        return sha.hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(obj, dict), f'Ожидается объект в {path.name}')
    return obj


def write_report(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_bytes(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False).encode('utf-8') + b'\n')
    os.replace(tmp, path)


def mac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def read_secret(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), 'Ключ теневого режима должен быть обычным файлом, а не символической ссылкой')
    if os.name != 'nt':
        require(path.stat().st_mode & 0o077 == 0, 'Небезопасные права доступа к ключу теневого режима')
    key = bytes.fromhex(path.read_text(encoding='ascii').strip())
    require(len(key) == 32, 'Ключ теневого режима должен содержать 32 случайных байта')
    return key


def verify_shadow_file(path: Path, key: bytes) -> list[dict]:
    require(path.is_file() and not path.is_symlink(), 'Журнал теневого режима не является обычным файлом')
    require(path.stat().st_size <= 128 * 1024 * 1024, 'Журнал теневого режима превышает лимит размера файла')
    previous, boot, last_ts = '', None, 0
    events: list[dict] = []
    with path.open('rb') as stream:
        for line_number, line in enumerate(stream, 1):
            require(line.endswith(b'\n') and len(line) <= 2048, f'{path.name}:{line_number}: усечённое или слишком большое событие')
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError) as exc:
                raise EvidenceError(f'{path.name}:{line_number}: некорректный JSON') from exc
            require(isinstance(record, dict), 'Запись теневого режима не является объектом')
            fields = {'schema', 'version', 'bootId', 'sequence', 'prevMac', 'timestampMs', 'sessionKey', 'nodeKey', 'outcome', 'reason', 'durationUs', 'mac'}
            require(set(record) == fields, f'{path.name}:{line_number}: неподдерживаемые поля')
            signature = record.pop('mac')
            require(isinstance(signature, str) and bool(HEX.fullmatch(signature)), 'Некорректное кодирование MAC теневого режима')
            expected = mac(key, canonical(record))
            require(hmac.compare_digest(expected, signature), f'{path.name}:{line_number}: проверка MAC не пройдена')
            require(record['schema'] == 'neverlauncher.guard-shadow/v1' and record['version'] == VERSION, 'Несовместимая схема или версия теневого режима')
            require(isinstance(record['bootId'], str) and BOOT.fullmatch(record['bootId']), 'Неверный идентификатор загрузки')
            require(boot is None or boot == record['bootId'], 'Смешанные идентификаторы загрузки')
            boot = record['bootId']
            require(type(record['sequence']) is int and record['sequence'] == line_number, 'Последовательность теневого режима отсутствует или воспроизведена повторно')
            require(record['prevMac'] == previous, 'Нарушена цепочка записей теневого режима')
            require(type(record['timestampMs']) is int and 1_500_000_000_000 < record['timestampMs'] <= int(time.time() * 1000) + 300_000 and record['timestampMs'] >= last_ts, 'Недопустимое или немонотонное время наблюдения')
            last_ts = record['timestampMs']
            for name in ('sessionKey', 'nodeKey'):
                require(isinstance(record[name], str) and bool(HEX.fullmatch(record[name])), f'некорректное значение {name}')
            require(record['outcome'] in ('allowed', 'revoked'), 'Неподдерживаемый результат теневого режима')
            require(isinstance(record['reason'], str) and bool(SAFE.fullmatch(record['reason'])), 'Причина содержит чувствительные данные или некорректна')
            require((record['reason'] == 'none') == (record['outcome'] == 'allowed'), 'Недопустимое сочетание результата и причины')
            require(type(record['durationUs']) is int and 0 <= record['durationUs'] <= 600_000_000, 'Недопустимая длительность проверки')
            record['mac'] = signature
            record['sourceFileSha256'] = None
            events.append(record)
            previous = signature
    require(bool(events), f'{path.name}: пустой журнал теневого режима')
    return events


def percentile(values: list[float], q: float) -> float:
    require(bool(values) and 0 <= q <= 1, 'Отсутствуют значения или недопустим квантиль')
    s = sorted(values)
    pos = (len(s) - 1) * q
    lower = math.floor(pos)
    return s[lower] + (s[min(lower + 1, len(s) - 1)] - s[lower]) * (pos - lower)


def analyze_shadow(folder: Path, key_path: Path, reviews_path: Path | None = None) -> dict:
    key = read_secret(key_path)
    paths = sorted(folder.glob('guard-shadow-*.jsonl'))
    require(bool(paths), 'Не переданы реальные журналы теневого режима ServerBridge')
    events, files, boot_seen = [], [], set()
    for path in paths:
        found = verify_shadow_file(path, key)
        boot_id = found[0]['bootId']
        require(boot_id not in boot_seen, 'Повторяющийся журнал загрузки (повторное воспроизведение)')
        boot_seen.add(boot_id)
        files.append({'name': path.name, 'sha256': file_hash(path), 'events': len(found)})
        events.extend(found)
    unique_macs = {v['mac'] for v in events}
    require(len(unique_macs) == len(events), 'Повторно воспроизведён MAC события')
    sessions: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        sessions[event['sessionKey']].append(event)
    observed_ms = 0
    revoked_events: list[dict] = []
    durations = []
    for history in sessions.values():
        history.sort(key=lambda row: (row['timestampMs'], row['bootId'], row['sequence']))
        previous = None
        for item in history:
            durations.append(item['durationUs'] / 1000.0)
            if previous and previous['outcome'] == 'allowed' and item['outcome'] == 'allowed':
                delta = item['timestampMs'] - previous['timestampMs']
                if 0 <= delta <= 30_000:
                    # Консервативная нижняя граница: учитываются только промежутки, покрытые двумя
                    # независимыми успешными проверками активной SQL-сессии.
                    observed_ms += delta
            if item['outcome'] == 'revoked':
                revoked_events.append(item)
            previous = item
    reviews: dict[str, str] = {}
    if reviews_path is not None:
        require(reviews_path.is_absolute() and reviews_path.is_file() and not reviews_path.is_symlink()
                and reviews_path.stat().st_nlink == 1 and
                0 < reviews_path.stat().st_size <= 8 * 1024 * 1024 and
                not any(p.is_symlink() for p in reviews_path.parents),
                'Журнал проверки должен быть обычным файлом ограниченного размера, не символьной ссылкой')
        def no_duplicate_json_fields(pairs):
            obj = {}
            for key, value in pairs:
                require(key not in obj, 'Повторяющееся поле JSON разбора инцидента')
                obj[key] = value
            return obj
        with reviews_path.open('rb') as f:
            for index, line in enumerate(f, 1):
                require(line.endswith(b'\n') and len(line) <= 2048,
                        f'review {index}: усечённая или слишком большая запись инцидента')
                try:
                    row = json.loads(line, object_pairs_hook=no_duplicate_json_fields)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise EvidenceError(f'Проверка {index}: некорректный JSON инцидента') from exc
                require(isinstance(row, dict) and set(row) == {'eventMac', 'verdict', 'reviewerId'}, f'review {index}: некорректные поля')
                evidence = row['eventMac']
                require(isinstance(evidence, str) and bool(HEX.fullmatch(evidence)) and evidence in unique_macs, f'review {index}: неизвестное событие')
                require(row['verdict'] in ('false_positive', 'true_positive', 'inconclusive'), f'review {index}: недопустимый вердикт')
                require(isinstance(row['reviewerId'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{1,63}', row['reviewerId']) is not None,
                        f'review {index}: некорректные данные проверяющего')
                require(evidence not in reviews, f'review {index}: повторная проверка')
                reviews[evidence] = row['verdict']
    invalid_reviews = [v for v in reviews if v not in {e['mac'] for e in revoked_events}]
    require(not invalid_reviews, 'Разбор должен относиться к фактически отозванному событию')
    counts = {v: sum(1 for e in revoked_events if reviews.get(e['mac']) == v) for v in ('false_positive', 'true_positive', 'inconclusive')}
    missing = len(revoked_events) - sum(counts.values())
    hours = round(observed_ms / 3_600_000, 6)
    # Барьер пилотной эксплуатации требует независимого подтверждения человеко-часов игроков и фактической
    # проверки внешним оператором, а не времени в журнале по собственным утверждениям.
    return {
        'schema': 'neverlauncher.guard-shadow-analysis/v1', 'version': VERSION,
        'status': 'BLOCKED' if hours < 10_000 or missing or counts['inconclusive'] or counts['false_positive'] else 'EVIDENCE_REVIEW_REQUIRED',
        'observedGuardActiveHoursLowerBound': hours,
        'playerHoursCertified': False,
        'requiredLegitimatePlayerHours': 10_000,
        'totalEvents': len(events), 'uniquePseudonymousSessions': len(sessions),
        'revokedEvents': len(revoked_events), 'unreviewedRevocations': missing,
        'reviewed': counts,
        'serverCheckP95Ms': round(percentile(durations, .95), 3),
        'files': files,
        'notes': 'Наблюдения основаны на подтверждённых серверных сигналах присутствия, а не на свежей аттестации памяти клиента. Требуются ручной разбор инцидентов и независимые сведения о реальных часах игры.',
    }


def load_frame_capture(folder: Path) -> tuple[dict, list[float], dict]:
    details = read_json(folder / 'capture.json')
    for field in ('os', 'arch', 'cpu', 'gpu', 'minecraftVersion', 'loader', 'scene', 'buildSha256', 'sourceTool'):
        require(isinstance(details.get(field), str) and details[field].strip(), f'Отсутствует запись захвата {field}')
    require(HEX.fullmatch(details['buildSha256']) is not None, 'Некорректный SHA-256 сборки')
    require(details['sourceTool'] in ('PresentMon', 'MangoHud', 'CapFrameX', 'RenderDoc', 'MinecraftFrameProfiler'), 'Для измерений кадров требуется известный инструмент реального захвата кадров')
    csvfile = folder / 'frames.csv'
    require(csvfile.is_file() and not csvfile.is_symlink() and csvfile.stat().st_size <= 64 * 1024 * 1024, 'Файл CSV с измерениями кадров отсутствует или повреждён')
    values = []
    with csvfile.open(newline='', encoding='utf-8-sig') as handle:
        rows = csv.DictReader(handle)
        require(rows.fieldnames is not None and 'frameTimeMs' in rows.fieldnames, 'Файл frames.csv должен содержать измеренные значения frameTimeMs')
        for row in rows:
            try: value = float(row['frameTimeMs'])
            except (ValueError, TypeError) as exc: raise EvidenceError('Некорректное время кадра') from exc
            require(math.isfinite(value) and 0.05 <= value <= 5000.0, 'Недопустимое записанное время кадра')
            values.append(value)
            require(len(values) <= 2_000_000, 'Слишком много кадров')
    require(len(values) >= 600, 'Для каждого захвата требуется не менее 600 измеренных кадров')
    return details, values, {'metadataSha256': file_hash(folder / 'capture.json'), 'framesSha256': file_hash(csvfile), 'frames': len(values)}


def compare_performance(base: Path, protected: Path) -> dict:
    a, av, ah = load_frame_capture(base)
    b, bv, bh = load_frame_capture(protected)
    require(a == b, 'Для A/B-проверки метаданные ОС, CPU, GPU, сборки, сцены, загрузчика и инструмента должны точно совпадать')
    p0, p1 = percentile(av, .95), percentile(bv, .95)
    change = (p1 / p0 - 1) * 100
    return {
        'schema': 'neverlauncher.guard-frame-performance/v1', 'version': VERSION,
        'status': 'PASS_MEASURED' if change <= 3.0 else 'FAIL_BUDGET',
        'baselineP95FrameMs': round(p0, 4), 'guardP95FrameMs': round(p1, 4),
        'guardP95RegressionPercent': round(change, 3), 'initialBudgetPercent': 3.0,
        'baseline': ah, 'protected': bh,
        'environment': a,
        'notes': 'Измерялись только два указанных внешних файла захвата кадров; это не сертификация производительности на разных конфигурациях оборудования.',
    }


def verify_game(work: Path, server_log: Path, username: str) -> dict:
    result = read_json(work / 'result.json')
    require(result.get('status') == 'passed' and result.get('version') == VERSION, 'Результат реальной E2E-проверки Minecraft отсутствует либо версия не совпадает')
    game = result.get('minecraft', {})
    checks = result.get('checks', {})
    require(isinstance(game, dict) and game.get('client') == 'actual-mojang-client' and game.get('paperJoin') == 'passed', 'Не подтверждено реальное подключение клиента Mojang к серверу')
    for check in ('packageVerified', 'signedManifest', 'actualClient', 'paperJoin', 'sessionRevokeDeny'):
        require(checks.get(check) is True, f'Проверка Minecraft E2E не пройдена: {check}')
    require(game.get('loader') in ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge'), 'Недопустимый загрузчик')
    if game['loader'] != 'vanilla':
        require(checks.get('loaderNativeClientJoin') is True, 'Клиент с модификациями не подключился к реальному серверу загрузчика')
    require((work / 'runtime-launch-minecraft.json').is_file(), 'Отсутствует реальное E2E-подтверждение: runtime-launch-minecraft.json')
    launch = read_json(work / 'runtime-launch-minecraft.json')
    require(launch.get('success') is True or launch.get('timedOut') is True, 'Реальный игровой процесс не запускался')
    evidence = result.get('evidence')
    require(isinstance(evidence, list) and evidence and len(evidence) == len(set(evidence)), 'Нет уникальных ссылок на E2E-подтверждения Minecraft')
    hashed = {}
    root = work.resolve()
    for name in evidence:
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,120}', name), 'Небезопасное имя файла свидетельства')
        target = work / name
        require(target.is_file() and not target.is_symlink() and target.resolve().parent == root and target.stat().st_size > 0, f'Отсутствует реальное свидетельство E2E: {name}')
        hashed[name] = file_hash(target)
    require(server_log.is_file() and not server_log.is_symlink() and re.fullmatch(r'[A-Za-z0-9_]{3,16}', username) is not None, 'Требуются журнал сервера и действительная учётная запись игрока Minecraft')
    # Сопоставляйте аутентифицированное разрешение сервера и фактическое сообщение о входе Minecraft
    # в одном захваченном серверном журнале, а не с поддельным main клиента.
    with server_log.open('r', encoding='utf-8', errors='replace') as log:
        seen_allow, seen_join = False, False
        for line in log:
            seen_allow |= re.search(r'launcher\.join\.allowed username=' + re.escape(username) + r'(?![A-Za-z0-9_])', line) is not None
            seen_join |= re.search(r'(?<![A-Za-z0-9_])' + re.escape(username) + r' joined the game(?![A-Za-z0-9_])', line) is not None
    require(seen_allow and seen_join, 'Сервер не зарегистрировал одновременно авторизованный допуск и фактическое подключение игрока')
    return {
        'schema': 'neverlauncher.guard-real-game-evidence/v1', 'version': VERSION,
        'status': 'EVIDENCE_VERIFIED_NOT_INDEPENDENT',
        'loader': game['loader'], 'minecraftVersion': game.get('version'),
        'gameResultSha256': file_hash(work / 'result.json'),
        'serverLogSha256': file_hash(server_log), 'evidenceSha256': hashed,
        'notes': 'Проверены артефакты реального запуска и журнал подключений Paper; это не независимое подтверждение длительности игрового процесса или работы всех датчиков Guard.',
    }


def run_jvm_suites(output: Path, only: set[str] | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    suites = []
    for name, rel, minimum in SUITES:
        if only is not None and name not in only:
            continue
        if name == 'linux-process-protection' and not sys.platform.startswith('linux'):
            suites.append({'name': name, 'status': 'UNSUPPORTED', 'reason': 'Требуется нативная JVM Linux'})
            continue
        script = ROOT / rel
        if not script.is_file():
            suites.append({'name': name, 'status': 'BLOCKED', 'reason': 'Отсутствует набор реально выполняемых проверок'})
            continue
        started = time.monotonic()
        try:
            proc = subprocess.run([sys.executable, str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=260, check=False)
            output_bytes = proc.stdout
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            output_bytes = exc.stdout or b''
            exit_code = 124
        text = output_bytes.decode('utf-8', errors='replace')
        # Журнал может содержать пути библиотек, но не учётные данные; сырые доказательства храните
        # локально с жёсткими правами, а в выпускных отчётах оставляйте только хеши.
        log = output / (name + '.log')
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(output_bytes)
        found = re.findall(r'Ran (\d+) tests? in [0-9.]+s', text)
        count = int(found[-1]) if found else 0
        passed = exit_code == 0 and count >= minimum and re.search(r'(?m)^OK\s*$', text) is not None and not re.search(r'\bskipped=\d+\b', text)
        suites.append({'name': name, 'status': 'PASS' if passed else 'FAIL',
                       'exitCode': exit_code, 'testsRun': count, 'minimumTests': minimum,
                       'durationSeconds': round(time.monotonic() - started, 2),
                       'logSha256': digest(output_bytes), 'logFile': log.name})
    status = 'PASS_JVM_REGRESSIONS_ONLY' if suites and all(v['status'] == 'PASS' for v in suites) else 'BLOCKED'
    return {'schema': 'neverlauncher.guard-adversarial-jvm/v1', 'version': VERSION,
            'status': status, 'suites': suites,
            'notes': 'Реальные тестовые Java-подпроцессы; это не сертификация официального Minecraft или пользовательского теневого пилота.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('run-jvm', help="Выполнить настоящие отрицательные тесты Java Agent и проверки совместимости")
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--only', choices=[row[0] for row in SUITES], action='append')
    p = sub.add_parser('analyze-shadow', help="Проверить серверно-аутентифицированный теневой журнал HMAC и подсчитать реальные наблюдения")
    p.add_argument('--journal-dir', type=Path, required=True)
    p.add_argument('--key-file', type=Path, required=True)
    p.add_argument('--reviews', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('compare-frame-times', help="Сопоставить два настоящих захвата кадров игры с инструментированием")
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--guard', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('verify-game', help="Проверить существующий реальный результат Minecraft E2E и журнал входа Paper")
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--paper-log', type=Path, required=True)
    p.add_argument('--username', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'run-jvm': report = run_jvm_suites(args.output.parent / 'logs', set(args.only) if args.only else None)
        elif args.command == 'analyze-shadow': report = analyze_shadow(args.journal_dir, args.key_file, args.reviews)
        elif args.command == 'compare-frame-times': report = compare_performance(args.baseline, args.guard)
        else: report = verify_game(args.work, args.paper_log, args.username)
        write_report(args.output, report)
        print(json.dumps({'status': report['status'], 'report': str(args.output)}, ensure_ascii=False))
        return 0 if report['status'].startswith('PASS') or report['status'] in ('EVIDENCE_VERIFIED_NOT_INDEPENDENT', 'EVIDENCE_REVIEW_REQUIRED') else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'Guard 0.50.12 ЗАБЛОКИРОВАН: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

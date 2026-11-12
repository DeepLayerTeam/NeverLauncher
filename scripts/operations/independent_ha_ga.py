#!/usr/bin/env python3
"""Независимая приёмка HA на реальных системах Launcher 0.52.0.

Симулированный результат, автономный манифест или вывод модульных тестов не разрешают GA. Оператор
запускает живые многохостовые хаос-тесты, поэтапные обновления и проверки восстановленного узла
штатными производственными командами. Каждый этап имеет закрытую эксклюзивную квитанцию с привязкой
к точному набору пакетов, исходному коммиту и независимому наблюдателю. Итоговое GA намеренно
BLOCKED, пока не получены независимо подписанные свидетельства *физического* отказа, разделения
инфраструктуры, зависимостей, уведомлений, миров и финальных нативных пакетов. Модульные
Python-тесты в CI никогда не выдают производственные квитанции.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import tarfile
import zipfile
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import multi_host_0512 as multi
import nn1_compat_0516 as compat

VERSION = '0.52.0'
SCHEMA = 'launcher.ha-independent-acceptance/0.52.0'
CHAOS_SCHEMA = 'launcher.multi-host-chaos/0.51.10'
ROLL_SCHEMA = 'launcher.rolling-update.0.52.0'
DR_SCHEMA = 'launcher.cross-host-recovery/0.51.9'
COMMANDS = {
    'chaos': ROOT / 'scripts/operations/multi_host_chaos_05110.py',
    'rolling': ROOT / 'scripts/operations/rolling_update_0520.py',
    'recovery': ROOT / 'scripts/operations/multi_host_0512.py',
    'bundle': ROOT / 'scripts/release/delivery_verify_0462.py',
}
STAGES = ('chaos', 'rolling', 'recovery', 'bundle')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
IDENTITY = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z')
MAX_JSON = 4 * 1024 * 1024

class Blocked(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def utc():
    return datetime.now(timezone.utc).isoformat()


def hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def unique(pairs):
    data = {}
    for name, value in pairs:
        require(name not in data, 'Повторяющееся поле объекта JSON')
        data[name] = value
    return data


def read_json(path, *, private=False):
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            'Доказательства JSON отсутствуют или небезопасны')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_JSON,
            'Недопустимый размер или тип доказательства')
    if private:
        require(stat.S_IMODE(info.st_mode) & 0o077 == 0, 'Файл закрытых подтверждений должен иметь права 0600')
    try:
        result = json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise Blocked('Некорректный JSON свидетельств') from exc
    require(isinstance(result, dict), 'Корень подтверждений должен быть объектом')
    return result


def fresh_output(path):
    require(path.is_absolute() and not path.exists() and not path.is_symlink(),
            'Путь вывода должен быть абсолютным и ещё не использоваться')
    parent = path.parent
    require(parent.is_dir() and not parent.is_symlink() and
            stat.S_IMODE(parent.stat().st_mode) & 0o077 == 0 and
            parent.stat().st_uid == os.geteuid(),
            'Каталог доказательств должен иметь права 0700 и принадлежать выполняющему оператору')


def write_receipt(path, result):
    fresh_output(path)
    raw = (json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode()
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as sink:
        sink.write(raw)
        sink.flush()
        os.fsync(sink.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def operator(primary):
    # Не принимайте произвольную строку --reviewer вместо идентичности ОС.
    require(bool(IDENTITY.fullmatch(primary or '')), 'Требуется действующий издатель или основной оператор')
    name = pwd.getpwuid(os.getuid()).pw_name
    if os.geteuid() == 0:
        name = os.environ.get('SUDO_USER', '')
        require(name and name != 'root', 'Для независимой операции от root требуется указанный источник sudo')
    require(bool(IDENTITY.fullmatch(name)) and name != primary,
            'Приёмку должен проводить другой оператор, прошедший аутентификацию в ОС')
    machine = multi.inventory.machine_identity()
    require(machine, 'Машина наблюдателя должна иметь устойчивый независимый идентификатор')
    return name, machine


def execute(path, args, timeout, *, json_output=True):
    require(path in COMMANDS.values(), 'Неподдерживаемый исполняемый файл для независимой приёмки')
    try:
        completed = subprocess.run([sys.executable, str(path), *args], timeout=timeout,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked('Реальная операция завершилась ошибкой или превысила время ожидания: ' + path.name) from exc
    require(completed.returncode == 0 and len(completed.stdout) <= MAX_JSON,
            'Проверка реальной эксплуатации не пройдена: ' + path.name)
    if not json_output:
        require(not completed.stdout.strip(), "Неожиданный стандартный вывод контроллера выпусков")
        return None
    try:
        response = json.loads(completed.stdout, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise Blocked('Реальная операция не вернула проверенный JSON: ' + path.name) from exc
    require(isinstance(response, dict), 'Реальная операция вернула неожиданный результат')
    return response


def nodes_from_args(args):
    nodes = multi.parse_nodes(args.node)
    require(len(nodes) >= 2, 'Для независимой многоузловой приёмки нужны минимум два физических узла')
    require(args.directory.startswith('/'), 'Путь к каталогу развёртывания должен быть абсолютным')
    require(multi.PROJECT_REGEX.fullmatch(args.project), 'Недопустимый проект')
    multi.validate_edge_url(args.edge_url)
    return nodes


def observe(args, *, expected=VERSION):
    nodes = nodes_from_args(args)
    reports = multi.collect_cluster(nodes, args.remote_script, args.directory,
                                    args.project, 'local-compat-observe', growth=True)
    versions = compat.validate_live_nodes(reports, pair=frozenset({expected}))
    require(set(versions.values()) == {expected}, 'Реальные процессы выполняют не тот выпуск')
    catalog, digest = compat.migration_catalog()
    compat.validate_schema(compat.live_pg_migrations(Path(args.pg_dsn_file)), catalog)
    good, samples = multi.edge_ready(args.edge_url)
    require(good and samples.get('sampled') == samples.get('success'),
            'Внешний HTTPS-вход работает нестабильно')
    local_machine = multi.inventory.machine_identity()
    require(all(row.get('machineIdentity') != local_machine for row in reports.values()),
            'Узел наблюдения не должен совпадать с одной из целевых машин Docker')
    return {'nodes': {name: {'machineIdentity': row['machineIdentity'], 'nodeId': row['nodeId'],
                             'imageDigest': row['imageDigestRefs']['api'], 'version': versions[name]}
                      for name, row in sorted(reports.items())},
            'postgresCatalogSha256': digest, 'postgresMigrations': len(catalog),
            'ingress': {'success': samples['success'], 'sampled': samples['sampled']}}


def verify_suite(home, nodes, iterations):
    summary_path = home / 'suite-report.json'
    data = read_json(summary_path, private=True)
    require(data.get('schema') == CHAOS_SCHEMA and data.get('status') == 'PASS' and
            data.get('iterations') == iterations, 'Набор испытаний отказоустойчивости на нескольких узлах не пройден')
    rows = data.get('cases')
    require(isinstance(rows, list) and len(rows) == 2 * len(nodes) * iterations,
            'В испытаниях отказоустойчивости отсутствует сценарий отказа или узел')
    seen, digests = set(), {}
    for row in rows:
        require(isinstance(row, dict), 'Недопустимый сценарий отказоустойчивости')
        key = (row.get('node'), row.get('fault'), row.get('iteration'))
        require(key not in seen and key[0] in nodes and key[1] in ('host-stop', 'network-partition')
                and type(key[2]) is int and 1 <= key[2] <= iterations,
                'Неожиданная или повторяющаяся цель имитации отказа')
        seen.add(key)
        basename = f'{key[2]:02d}-{key[0]}-{key[1]}.report.json'
        require(row.get('reportFile') == basename and row.get('status') == 'PASS'
                and row.get('recovered') is True, 'Сценарий отказа завершился неуспешно или система не восстановилась')
        file = home / basename
        case = read_json(file, private=True)
        require(hash_file(file) == row.get('sha256') and
                case.get('schema') == CHAOS_SCHEMA and case.get('status') == 'PASS'
                and case.get('recoveredAndVerified') is True and
                case.get('failedNode') == key[0] and case.get('fault') == key[1] and
                case.get('evidence', {}).get('faultObserved') is True and
                case.get('evidence', {}).get('alertState') == 'ACTIVE' and
                isinstance(case.get('evidence', {}).get('ingressSamples'), list) and
                len(case['evidence']['ingressSamples']) >= 8 and
                all(item.get('ingressReady') is True for item in
                    case['evidence']['ingressSamples'][-5:]),
                'Байты, оповещения или результат проверки входящего трафика не совпадают с квитанцией испытаний')
        digests[basename] = hash_file(file)
        require(not (home / basename.replace('.report.json', '.state.json')).exists(),
                'Остался журнал невосстановленного отказа')
    return {'summarySha256': hash_file(summary_path), 'caseSha256': digests,
            'cases': len(rows), 'faultTypes': ['host-stop', 'network-partition']}


def validate_rolling(path, nodes):
    result = read_json(path, private=True)
    require(result.get('schema') == ROLL_SCHEMA and result.get('verified') is True and
            result.get('from') == '0.51.10' and result.get('to') == VERSION,
            'Поэтапная операция обновления 0.51.10 → 0.52.0 не подтверждена')
    versions = result.get('finalVersions')
    require(isinstance(versions, dict) and set(versions) == set(nodes) and
            all(value == VERSION for value in versions.values()),
            'Поэтапное обновление проверено не на всех целевых узлах')
    steps = result.get('steps')
    require(isinstance(steps, list) and len(steps) == len(nodes) and
            all(item.get('verified') is True and item.get('edgeFailures') == 0 and
                type(item.get('edgeSamples')) is int and item['edgeSamples'] >= 2 for item in steps),
            'При поэтапном обновлении не проверялась непрерывная доступность входящего трафика каждого узла')
    require(len({item.get('nodeId') for item in steps}) == len(nodes),
            'Квитанции поэтапного обновления содержат повторяющиеся идентификаторы физических узлов')
    return {'receiptSha256': hash_file(path), 'steps': len(steps),
            'finalVersions': versions, 'edgeFailures': 0}


def validate_recovery(work, maximum_rto, maximum_sample_rpo, nodes):
    require(work.is_absolute() and work.is_dir() and not work.is_symlink(), 'Рабочий каталог аварийного восстановления недоступен')
    state_path = work / 'recovery-state-0519.json'
    result_path = work / 'recovery-result-0519.json'
    state, result = read_json(state_path, private=True), read_json(result_path, private=True)
    require(isinstance(state.get('nodes'), dict) and state['nodes'] == nodes,
            'Восстановленные аварийные узлы не совпадают с независимо проверенными целями')
    require(state.get('schema') == DR_SCHEMA and state.get('phase') == 'recovery-ready'
            and result.get('schema') == DR_SCHEMA and result.get('status') == 'recovery-ready'
            and result.get('runId') == state.get('runId') and
            type(result.get('nodesReady')) is int and result['nodesReady'] == len(nodes) and
            type(result.get('worlds')) is int and result['worlds'] > 0,
            'Аварийное восстановление миров не выполнено на всех целевых узлах')
    rto = result.get('rtoSeconds')
    require(type(rto) in (int, float) and 0 <= rto <= maximum_rto,
            'Измеренное время восстановления внешнего доступа (RTO) превышает допустимое значение')
    sample = result.get('sampledRpo')
    require(isinstance(sample, dict) and sample.get('sampledAuditRpoSeconds') is not None,
            'Для измерения выборочного RPO нужен независимый журнал подтверждений')
    rpo = sample['sampledAuditRpoSeconds']
    require(type(rpo) in (int, float) and 0 <= rpo <= maximum_sample_rpo,
            'Измеренное RPO аудита превышает допустимое значение')
    return {'recoveryStateSha256': hash_file(state_path),
            'recoveryResultSha256': hash_file(result_path), 'runId': result['runId'],
            'rtoSeconds': rto, 'sampledAuditRpoSeconds': rpo,
            'scopeLimit': 'RPO входящего трафика управляющего контура и выборочного аудита; не RPO игрового мира'}


def receipt(args, stage, actor, machine, details, observed=None):
    return {'schema': SCHEMA, 'stage': stage, 'status': 'OBSERVED', 'version': VERSION,
            'commit': args.commit, 'publisher': args.publisher, 'operator': actor,
            'observerMachine': machine, 'atUtc': utc(), 'project': args.project,
            'edgeOrigin': args.edge_url.split('/ready')[0], 'details': details,
            'liveCluster': observed}


def stage(args):
    actor, machine = operator(args.publisher)
    require(COMMIT.fullmatch(args.commit or '') is not None, 'Требуется хеш коммита выпуска длиной 40 символов')
    require((ROOT / 'VERSION').read_text().strip() == VERSION, 'Рабочая копия исходников имеет неверную версию')
    nodes = nodes_from_args(args)
    target = Path(args.output)
    fresh_output(target)
    before = None
    if args.stage == 'chaos':
        require(args.allow_disruption and 1 <= args.iterations <= 3 and args.alertmanager_url,
                'Необходимо явно указать --allow-disruption, --alertmanager-url и число повторов от 1 до 3')
        multi.validate_edge_url(args.alertmanager_url)
        before = observe(args, expected=VERSION)
        home = Path(args.suite_directory)
        require(home.is_absolute() and home.is_dir() and not home.is_symlink(),
                'Необходимо подготовить пустой закрытый каталог испытаний отказоустойчивости')
        outcome = execute(COMMANDS['chaos'], ['suite', '--directory', args.directory,
            '--project', args.project, '--edge-url', args.edge_url,
            '--suite-directory', str(home), '--iterations', str(args.iterations),
            '--allow-disruption', 'I-ACCEPT-REAL-OUTAGE',
            '--alertmanager-url', args.alertmanager_url,
            '--multi-host-script', args.remote_script, '--chaos-script', args.chaos_script,
            *sum((['--node', node] for node in args.node), [])], 3600)
        require(outcome.get('status') == 'PASS', 'Реальная команда проверки отказоустойчивости завершилась ошибкой')
        details = verify_suite(home, nodes, args.iterations)
    elif args.stage == 'rolling':
        # Перед поэтапным обновлением требуйте N-1 работающих процессов; смешанное исходное
        # состояние не является свежим испытанием GA.
        before = observe(args, expected='0.51.10')
        require(args.allow_update, 'Для реального развёртывания OCI необходимо явно указать --allow-update')
        roll_path = target.with_name(target.name + '.rolling.json')
        fresh_output(roll_path)
        execute(COMMANDS['rolling'], ['cluster-roll', '--directory', args.directory,
            '--project', args.project, '--edge-url', args.edge_url,
            '--pg-dsn-file', args.pg_dsn_file, '--allow-update', '--output', str(roll_path),
            '--remote-script', args.remote_script, '--rolling-script', args.rolling_script,
            *sum((['--node', node] for node in args.node), [])], 3600, json_output=False)
        details = validate_rolling(roll_path, nodes)
    elif args.stage == 'recovery':
        # Восстановление должно действительно пройти этапы 0.51.9 prepare/replay/admit на
        # НОВЫХ физических хостах, а старый кластер должен быть отдельно изолирован.
        before = observe(args, expected=VERSION)
        details = validate_recovery(Path(args.recovery_work), args.maximum_rto,
                                    args.maximum_sample_rpo, nodes)
    else:
        raise Blocked('Неподдерживаемый этап приёмки реальной среды')
    after = observe(args, expected=VERSION)
    if before is not None:
        require(after['postgresCatalogSha256'] == before['postgresCatalogSha256'],
                'Схема изменилась при обновлении или испытаниях без совместимости expand-contract')
        require(set(after['nodes']) == set(before['nodes']) and
                all(after['nodes'][n]['machineIdentity'] == before['nodes'][n]['machineIdentity']
                    for n in nodes), 'Идентификаторы физических узлов изменились во время приёмки')
    write_receipt(target, receipt(args, args.stage, actor, machine, details, after))
    return target


def validate_stage_receipts(files, *, commit, publisher):
    seen, machine = set(), None
    docs = {}
    for path in files:
        data = read_json(path, private=True)
        name = data.get('stage')
        require(data.get('schema') == SCHEMA and data.get('status') == 'OBSERVED'
                and data.get('version') == VERSION and data.get('commit') == commit
                and data.get('publisher') == publisher and name in STAGES
                and name not in seen, 'Некорректная, повторная или относящаяся к другому выпуску квитанция')
        seen.add(name)
        require(isinstance(data.get('operator'), str) and data['operator'] != publisher and
                IDENTITY.fullmatch(data['operator']) is not None and
                isinstance(data.get('liveCluster'), (dict, type(None))),
                'Недопустимая квитанция независимого оператора')
        # ID машин-наблюдателей в инвентаризации — сокращённые отпечатки хостов.
        require(isinstance(data.get('observerMachine'), str) and
                data['observerMachine'].startswith('machine:'), 'Отсутствует отпечаток узла наблюдения')
        machine = machine or data['observerMachine']
        require(data['observerMachine'] == machine, 'Данные независимых машин-наблюдателей противоречат друг другу')
        docs[name] = data
    require(seen == set(STAGES), 'Требуются квитанции проверок отказов, обновлений, восстановления и пакетов')
    return docs, {read_json(path, private=True)['stage']: hash_file(path) for path in files}


def final_bundle(args):
    # Фактический каталог выпуска проверяется повторно, а не принимается из
    # сохранённых сведений.
    from delivery_verify_0462 import verify_bundle
    bundle = Path(args.bundle)
    require(bundle.is_absolute(), 'Конечный каталог загрузки должен иметь абсолютный путь')
    verified = verify_bundle(bundle, release_manifest=True)
    require(verified.get('version') == VERSION and len(verified.get('targets', {})) == 6,
            'Полная итоговая поставка для шести платформ не подтверждена')
    return {'releaseManifestSha256': hash_file(bundle / 'RELEASE_MANIFEST.json'),
            'targets': {k: v['sha256'] for k, v in verified['targets'].items()},
            'status': verified['status']}


def bundle_stage(args):
    actor, machine = operator(args.publisher)
    require(COMMIT.fullmatch(args.commit or '') is not None, 'Требуется коммит исходного кода')
    data = final_bundle(args)
    write_receipt(Path(args.output), receipt(args, 'bundle', actor, machine, data))


def gate(args):
    # Это намеренно независимая проверка с отказом по умолчанию, а НЕ
    # кнопка самоодобрения. Подпись и физическая сертификация инфраструктуры
    # нельзя установить по сетевым сбоям Docker и HTTP-проверкам.
    require(COMMIT.fullmatch(args.commit or '') is not None, 'Требуется коммит исходного кода')
    docs, receipts = validate_stage_receipts([Path(x) for x in args.receipt],
                                            commit=args.commit, publisher=args.publisher)
    expected = final_bundle(args)
    require(docs['bundle']['details'] == expected,
            'Байты итогового выпуска изменились после независимой проверки пакета')
    require(docs['rolling'].get('liveCluster') and docs['chaos'].get('liveCluster'),
            'Отсутствуют наблюдения реального обновления и испытаний отказоустойчивости')
    require(docs['rolling']['liveCluster']['nodes'] == docs['chaos']['liveCluster']['nodes'],
            'В испытаниях отказоустойчивости и поэтапной приёмке использовались разные наборы узлов или образов')
    require(docs['rolling']['details']['edgeFailures'] == 0 and
            docs['recovery']['details']['rtoSeconds'] <= args.maximum_rto,
            'Показатели отката или восстановления превышают допустимые значения')
    # Полный GA требует машинно-проверяемых свидетельств физических хостов/сети и внешних
    # свидетельства кворума, игровой процесс JVM и нативные подписи. Предыдущие этапы
    # не могут подтвердить их, и мы не должны незаметно превращать их в PASS.
    return {'schema': SCHEMA, 'version': VERSION, 'status': 'BLOCKED',
            'releaseManifestSha256': expected['releaseManifestSha256'],
            'receiptSha256': receipts,
            'missingIndependentEvidence': [
                'Физическое отключение питания и разрыв сети с независимой телеметрией',
                'Фактическое переключение лидера кворума PostgreSQL/Redis/S3 и проверка согласованности данных',
                'подтверждение получения уведомления конечным получателем',
                'Восстановленное состояние мира Minecraft и успешное независимое подключение к игре',
                'Подписание итоговых нативных пакетов для шести платформ и сквозные игровые проверки',
                'Подпись независимого проверяющего для полного набора итоговых подтверждений']}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('stage', choices=('chaos', 'rolling', 'recovery', 'bundle', 'gate'))
    ap.add_argument('--node', action='append', default=[])
    ap.add_argument('--project', default='launcher')
    ap.add_argument('--directory', default='/opt/launcher/deploy/production')
    ap.add_argument('--edge-url', default='')
    ap.add_argument('--remote-script', default='/opt/launcher/scripts/operations/multi_host_0512.py')
    ap.add_argument('--chaos-script', default='/opt/launcher/scripts/operations/multi_host_chaos_05110.py')
    ap.add_argument('--rolling-script', default='/opt/launcher/scripts/operations/rolling_update_0520.py')
    ap.add_argument('--pg-dsn-file', default='')
    ap.add_argument('--suite-directory', default='')
    ap.add_argument('--iterations', type=int, default=1)
    ap.add_argument('--allow-update', action='store_true')
    ap.add_argument('--allow-disruption', action='store_true')
    ap.add_argument('--alertmanager-url', default='')
    ap.add_argument('--recovery-work', default='')
    ap.add_argument('--maximum-rto', type=float, default=180)
    ap.add_argument('--maximum-sample-rpo', type=float, default=60)
    ap.add_argument('--bundle', default='')
    ap.add_argument('--commit', required=True)
    ap.add_argument('--publisher', required=True)
    ap.add_argument('--receipt', action='append', default=[])
    ap.add_argument('--output', default='')
    args = ap.parse_args(argv)
    try:
        if args.stage == 'bundle':
            require(args.output, 'Требуется --output')
            bundle_stage(args)
        elif args.stage == 'gate':
            result = gate(args)
            if args.output:
                write_receipt(Path(args.output), result)
            print(json.dumps(result, sort_keys=True))
            return 3
        else:
            require(args.output and args.pg_dsn_file and args.edge_url,
                    'Для реальной приёмки необходимы --output, --pg-dsn-file и --edge-url')
            stage(args)
        print(json.dumps({'status': 'OBSERVED', 'stage': args.stage, 'version': VERSION}))
        return 0
    except (Blocked, multi.DeploymentError, multi.inventory.InventoryError,
            compat.CompatibilityError, ValueError, OSError, KeyError, TypeError,
            zipfile.BadZipFile, tarfile.TarError) as exc:
        # Никогда не выводить исходную конфигурацию, stderr подпроцессов, учётные данные или DSN.
        print(json.dumps({'status': 'BLOCKED', 'stage': args.stage,
                          'reason': type(exc).__name__}), file=sys.stderr)
        return 3

if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""0.51.10: восстановимая инъекция сбоев на независимо управляемых Docker-хостах.

Запланированное разделение отключает реальные контейнеры API/worker от сети Docker, а не только
имитированный флаг готовности. Сценарии отказа хоста используют штатные реальные остановку/запуск
нескольких хостов. Устойчивый локальный журнал позволяет вручную переподключить сеть после
завершения SSH/оператора; оркестрация всегда пытается восстановить работу и отказывает в PASS без
повторной проверки всех узлов.

Эти сбои НЕ доказывают физическое отключение питания, fencing кворума хранилища или непрерывность
Minecraft JVM. Использовать одноразовый/тестовый проект с явным согласием.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import multi_host_0512 as multi

SCHEMA = 'neverlauncher.multi-host-chaos/0.51.10'
MAX_OUTPUT = 128_000
ROLES = ('api', 'worker')


class ChaosError(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise ChaosError(reason)


def utc():
    return datetime.now(timezone.utc).isoformat()


def private_regular(path: Path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
            (stat.S_IMODE(st.st_mode) & 0o077) == 0 and st.st_size <= 65536,
            'Файл должен быть обычным закрытым файлом с правами 0600')
    return path.read_bytes()


def save_new(path: Path, data: dict):
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'Небезопасный каталог состояния')
    serialized = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(serialized)
        out.flush()
        os.fsync(out.fileno())
    fsync_dir(path.parent)


def fsync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_private(path: Path, data: dict):
    if path.is_symlink():
        raise ChaosError('Небезопасная символическая ссылка на состояние')
    payload = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix='.chaos-05110-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_state(path):
    try:
        data = json.loads(private_regular(path))
        require(isinstance(data, dict) and data.get('schema') == SCHEMA,
                'Некорректный журнал восстановления после испытания сбоем')
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise ChaosError('Закрытый журнал восстановления отсутствует или некорректен') from exc


@contextmanager
def lock_for(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'Каталог состояния отсутствует либо является символической ссылкой')
    require(directory.stat().st_uid == os.geteuid() and not (directory.stat().st_mode & 0o022),
            'Каталог состояния должен принадлежать оператору и быть недоступен для записи группе и остальным')
    path = directory / '.multi-host-chaos-05110.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        require(stat.S_IMODE(os.fstat(fd).st_mode) & 0o077 == 0, 'Небезопасные права доступа к файлу блокировки')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ChaosError('Этот каталог уже занят другой операцией аварийного тестирования или восстановления') from exc
        yield
    finally:
        os.close(fd)


def invoke(argv, timeout=40):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ChaosError('Обязательная команда завершилась ошибкой или превысила время ожидания') from exc
    require(p.returncode == 0 and len(p.stdout) <= MAX_OUTPUT, 'Команда завершилась ошибкой либо вывод слишком велик')
    return p.stdout.decode('utf-8', 'strict').strip()


def local_compose_id(directory, project, role, *, allow_detached=False):
    value = invoke(multi.compose_command(directory, project, 'ps', '-q', role), 20)
    require(re.fullmatch('[0-9a-f]{12,64}', value), 'Отсутствует контейнер целевой роли')
    inspected = json.loads(invoke(['docker', 'inspect', value], 20))
    require(isinstance(inspected, list) and len(inspected) == 1, 'Результат проверки контейнера не соответствует ожиданиям')
    item = inspected[0]
    labels = (item.get('Config') or {}).get('Labels') or {}
    require(labels.get('com.docker.compose.project') == project and
            labels.get('com.docker.compose.service') == role,
            'Контейнер не принадлежит ожидаемому проекту или роли')
    networks = (item.get('NetworkSettings') or {}).get('Networks') or {}
    expected = project + '_launcher'
    require((not networks if allow_detached else expected in networks and len(networks) == 1) or
            (allow_detached and expected in networks and len(networks) == 1),
            'Сетевая топология контейнера не соответствует ожидаемой')
    return value, expected


def local_network_aliases(container_id, network, role):
    """Сохранять DNS служб Compose после ручного отключения/подключения сети Docker.

    Без явных псевдонимов сохранившийся ingress может возвращать 502, даже когда сетевое подключение
    контейнера формально восстановлено.
    """
    raw = json.loads(invoke(['docker', 'inspect', container_id], 20))
    require(isinstance(raw, list) and len(raw) == 1, 'Недопустимый результат проверки контейнера')
    networks = ((raw[0].get('NetworkSettings') or {}).get('Networks')) or {}
    require(network in networks, 'До изоляции отсутствует ожидаемая сеть Compose')
    aliases = (networks[network] or {}).get('Aliases') or []
    require(isinstance(aliases, list) and role in aliases, 'Отсутствует псевдоним службы Compose')
    good = sorted(set(aliases))
    require(len(good) <= 12 and all(isinstance(a, str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', a) for a in good),
            'Небезопасные DNS-псевдонимы Docker в сети Compose')
    return good


def inspect_network(container_id, network):
    inspected = json.loads(invoke(['docker', 'inspect', container_id], 20))
    require(isinstance(inspected, list) and len(inspected) == 1, 'Контейнер исчез')
    return network in (((inspected[0].get('NetworkSettings') or {}).get('Networks')) or {})


def local_consent(directory, project, approval):
    data = json.loads(private_regular(approval))
    require(isinstance(data, dict), 'Недопустимое разрешение на локальное нарушение работы')
    actual = multi.resolved_compose(directory, project)
    require(data.get('project') == project and data.get('nodeId') == actual['nodeId'] and
            data.get('allow') == ['network-partition'], 'Разрешение не относится к этому проекту, узлу или сбою')
    require(isinstance(data.get('expiresUtc'), str), 'Недопустимый срок действия разрешения')
    expires = datetime.fromisoformat(data['expiresUtc'].replace('Z', '+00:00'))
    require(expires.tzinfo is not None and datetime.now(timezone.utc) < expires.astimezone(timezone.utc) <=
            datetime.now(timezone.utc) + timedelta(hours=4),
            'Срок разрешения истёк или выходит за пределы текущих суток UTC')


def local_isolate(directory, project, approval):
    # При неопределённом частичном разрыве связи журнал сохраняется для последующего
    # восстановления.
    with lock_for(directory):
        local_consent(directory, project, approval)
        path = directory / '.multi-host-partition-05110.json'
        require(not path.exists() and not path.is_symlink(), 'Предыдущий локальный сбой не устранён; восстановите систему до следующего испытания')
        targets = [dict(role=role, container=cid, network=net,
                        aliases=local_network_aliases(cid, net, role))
                   for role in ROLES for cid, net in [local_compose_id(directory, project, role)]]
        require(len({t['network'] for t in targets}) == 1, 'Сети API и Worker различаются')
        state = {'schema': SCHEMA, 'project': project, 'createdUtc': utc(),
                 'phase': 'disconnecting', 'targets': targets}
        save_new(path, state)
        for entry in targets:
            invoke(['docker', 'network', 'disconnect', '--force', entry['network'], entry['container']], 30)
        state['phase'] = 'disconnected'
        replace_private(path, state)
        return {'schema': SCHEMA, 'project': project, 'partitionExecuted': True,
                'detachedRoles': list(ROLES)}


def local_status(directory, project):
    path = directory / '.multi-host-partition-05110.json'
    state = read_state(path)
    require(state.get('project') == project, 'Проект сетевой изоляции не совпадает')
    detached = []
    for t in state['targets']:
        require(t['role'] in ROLES and re.fullmatch(r'[0-9a-f]{12,64}', t['container']) and
                t['network'] == project + '_launcher', 'Небезопасное содержимое журнала')
        detached.append(not inspect_network(t['container'], t['network']))
    return {'schema': SCHEMA, 'project': project, 'partitionExecuted': all(detached),
            'detachedRoles': [t['role'] for t, value in zip(state['targets'], detached) if value]}


def local_heal(directory, project):
    with lock_for(directory):
        path = directory / '.multi-host-partition-05110.json'
        if not path.exists() and not path.is_symlink():
            return {'schema': SCHEMA, 'project': project, 'healed': True, 'hadJournal': False}
        state = read_state(path)
        require(state.get('project') == project, 'Нельзя восстановить другой проект')
        errors = []
        for item in state['targets']:
            role, ident, network = item['role'], item['container'], item['network']
            require(role in ROLES and re.fullmatch(r'[0-9a-f]{12,64}', ident) and
                    network == project + '_launcher', 'Небезопасный журнал восстановления')
            # Контейнер мог быть пересоздан; никогда не подключайтесь к произвольному ID.
            try:
                current, expected_net = local_compose_id(directory, project, role, allow_detached=True)
                require(current == ident and expected_net == network, 'Идентификатор контейнера изменился во время сетевой изоляции')
                if not inspect_network(ident, network):
                    aliases = item.get('aliases')
                    require(isinstance(aliases, list) and role in aliases and len(aliases) <= 12 and
                            all(isinstance(a, str) and re.fullmatch(
                                r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', a) for a in aliases),
                            'Некорректные сетевые псевдонимы в журнале восстановления')
                    command = ['docker', 'network', 'connect']
                    for alias in aliases:
                        command += ['--alias', alias]
                    invoke([*command, network, ident], 35)
                require(inspect_network(ident, network), 'Docker не подключил сеть повторно')
            except (ChaosError, OSError, ValueError):
                errors.append(role)
        if errors:
            state['phase'] = 'heal-required'
            replace_private(path, state)
            return {'schema': SCHEMA, 'project': project, 'healed': False, 'roles': errors}
        path.unlink()
        fsync_dir(directory)
        return {'schema': SCHEMA, 'project': project, 'healed': True, 'hadJournal': True}


def ssh_helper(target, script, directory, project, mode, *, approval=None):
    require(multi.HOST_REGEX.fullmatch(target) and not target.startswith('-'), 'Недопустимый целевой узел SSH')
    require(script.startswith('/') and directory.startswith('/') and '\n' not in script + directory,
            'Удалённые пути должны быть абсолютными и однострочными')
    require(mode in ('local-isolate', 'local-status', 'local-heal'), 'Неподдерживаемый удалённый режим')
    args = ['python3', script, mode, '--directory', directory, '--project', project]
    if approval and mode == 'local-isolate':
        require(approval.startswith('/') and '\n' not in approval, 'Некорректный путь к файлу разрешения')
        args += ['--approval-file', approval]
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=8', '-o', 'NumberOfPasswordPrompts=0', target, shlex.join(args)]
    result = json.loads(invoke(ssh, 110))
    require(isinstance(result, dict) and result.get('schema') == SCHEMA and result.get('project') == project,
            'Некорректный ответ удалённого испытания сбоем')
    return result


def assert_baseline(nodes, remote_script, directory, project, edge):
    reports = multi.collect_cluster(nodes, remote_script, directory, project, 'local-observe')
    check = multi.cluster_verify(reports, edge)
    require(check['multiHostControlPlaneObserved'], 'Базовая многоузловая конфигурация неисправна')
    return reports


def edge_survivor_probe(nodes, victim, remote_script, directory, project, edge, timeout, interval=1):
    observations = []
    begin = time.monotonic()
    healthy_streak = 0
    while time.monotonic() - begin < timeout:
        ok, sample = multi.edge_ready(edge, 1)
        observations.append({'elapsedMs': round((time.monotonic()-begin)*1000),
                             'ingressReady': ok, 'samples': sample['sampled']})
        if ok:
            healthy_streak += 1
        else:
            healthy_streak = 0
        if healthy_streak >= 3:
            break
        time.sleep(interval)
    require(healthy_streak >= 3, 'Публичный входящий трафик не восстановился через оставшийся узел')
    # Восстановленный балансировщик, сразу переходящий между состояниями, не
    # должен проходить проверку.
    for _ in range(5):
        time.sleep(interval)
        ok, sample = multi.edge_ready(edge, 1)
        observations.append({'elapsedMs': round((time.monotonic()-begin)*1000),
                             'ingressReady': ok, 'samples': sample['sampled']})
        require(ok, 'Во время наблюдения сбоя публичный входящий трафик был нестабилен')
    survivor = {}
    for name, target in nodes.items():
        if name == victim:
            continue
        status = multi.remote_call(target, remote_script, directory, project, 'local-observe')
        survivor[name] = status.get('ready') is True
    require(all(survivor.values()), 'Один или несколько оставшихся узлов API/Worker не прошли реальные проверки зависимостей')
    return observations, survivor


def endpoint_url(url):
    multi.validate_edge_url(url)
    return url.rstrip('/')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def alertmanager_observe(url, alert, deadline=45):
    endpoint_url(url)
    require(urlsplit(url).path in ('', '/'), 'Адрес Alertmanager должен быть HTTPS-источником')
    require(re.fullmatch(r'NeverLauncher[A-Za-z0-9]{2,80}', alert), 'Некорректное имя оповещения')
    op = urllib.request.build_opener(NoRedirect())
    until = time.monotonic() + deadline
    while time.monotonic() < until:
        try:
            with op.open(url.rstrip('/') + '/api/v2/alerts', timeout=8) as response:
                data = response.read(512_001)
            require(len(data) < 512_001, 'Ответ API оповещений слишком велик')
            alerts = json.loads(data)
            if isinstance(alerts, list) and any(isinstance(a, dict) and
                    (a.get('labels') or {}).get('alertname') == alert and
                    (a.get('status') or {}).get('state') == 'active' for a in alerts):
                return True
        except (OSError, urllib.error.HTTPError, ValueError):
            pass
        time.sleep(2)
    return False


def run_fault(args, nodes):
    report = Path(args.report).absolute()
    state_path = Path(args.state).absolute()
    require(report != state_path and not report.exists() and not report.is_symlink(),
            'Выходной отчёт уже существует')
    require(not state_path.exists() and not state_path.is_symlink(),
            'Обнаружен журнал невосстановленного сбоя; выполните recover')
    require(args.failed_node in nodes, 'Неизвестная цель проверки сбоя')
    require(len(nodes) >= 2, 'Требуются как минимум два хоста')
    require(args.allow_disruption == 'I-ACCEPT-REAL-OUTAGE', 'Требуется явное разрешение на реальное нарушение работы')
    require(15 <= args.timeout <= 300, 'Тайм-аут должен быть от 15 до 300 секунд')
    require(30 <= args.alert_timeout <= 300, 'Ожидание оповещения должно быть от 30 до 300 секунд')
    edge = endpoint_url(args.edge_url)
    # Подтверждение исходного состояния должно предшествовать любой записи
    # намерения отключения или удалённому изменению.
    assert_baseline(nodes, args.multi_host_script, args.directory, args.project, edge)
    intent = {'schema': SCHEMA, 'phase': 'intent', 'fault': args.fault, 'project': args.project,
              'failedNode': args.failed_node, 'createdUtc': utc(), 'nodes': nodes,
              'recoveryRequired': True}
    save_new(state_path, intent)
    start = time.monotonic()
    result = {'schema': SCHEMA, 'release': '0.51.10', 'fault': args.fault,
              'failedNode': args.failed_node, 'startedUtc': utc(), 'status': 'FAILED',
              'evidence': {'baseline': 'all-hosts-live-ready-and-independent', 'faultObserved': False,
                           'survivors': {}, 'ingressSamples': [], 'alertState': 'UNVERIFIED'},
              'scopeLimits': ['Сбои контейнеров или сети Docker, а не физическое отключение питания',
                              'Непрерывность Minecraft/JVM не подтверждается',
                              'Кворум PostgreSQL и однократность побочных действий не подтверждаются']}
    restore_success = False
    try:
        intent['phase'] = 'faulting'
        replace_private(state_path, intent)
        try:
            if args.fault == 'host-stop':
                stopped = multi.remote_stop_start(nodes[args.failed_node], args.multi_host_script,
                                                   args.directory, args.project, 'stop')
                require(stopped.get('executed') is True and stopped.get('action') == 'stop',
                        'Команда остановки не была выполнена')
                observed = multi.remote_call(nodes[args.failed_node], args.multi_host_script,
                                             args.directory, args.project, 'local-observe', growth=False)
                require(observed.get('ready') is False, 'Остановленный хост по-прежнему сообщает об исправном состоянии')
                result['evidence']['faultObserved'] = True
            else:
                ssh_helper(nodes[args.failed_node], args.chaos_script, args.directory,
                           args.project, 'local-isolate', approval=args.approval_file)
                status = ssh_helper(nodes[args.failed_node], args.chaos_script, args.directory,
                                    args.project, 'local-status')
                require(status.get('partitionExecuted') is True and
                        set(status.get('detachedRoles', [])) == set(ROLES),
                        'Разделение сети не изолировало обе роли контейнеров')
                result['evidence']['faultObserved'] = True
            intent['phase'] = 'fault-active'
            replace_private(state_path, intent)
            samples, survivor = edge_survivor_probe(nodes, args.failed_node, args.multi_host_script,
                                                      args.directory, args.project, edge, args.timeout)
            result['evidence']['ingressSamples'] = samples
            result['evidence']['survivors'] = survivor
            result['failoverSeconds'] = round(time.monotonic()-start, 3)
            if args.alertmanager_url:
                result['evidence']['alertState'] = ('ACTIVE' if alertmanager_observe(args.alertmanager_url,
                    args.alert_name, args.alert_timeout) else 'NOT_OBSERVED')
            result['status'] = 'PASS' if (not args.alertmanager_url or
                                    result['evidence']['alertState'] == 'ACTIVE') else 'FAIL'
        except (ChaosError, multi.DeploymentError, multi.inventory.InventoryError, OSError, ValueError):
            result['status'] = 'FAIL'
            result['failure'] = 'Проверка сбоя не пройдена; изучите журналы оператора'
        finally:
            # Всегда пытайтесь восстановить систему, даже если первоначальная SSH-команда
            # превысила время ожидания.
            intent['phase'] = 'restoring'
            replace_private(state_path, intent)
            try:
                if args.fault == 'host-stop':
                    multi.remote_stop_start(nodes[args.failed_node], args.multi_host_script,
                                            args.directory, args.project, 'start')
                else:
                    recovered = ssh_helper(nodes[args.failed_node], args.chaos_script,
                                           args.directory, args.project, 'local-heal')
                    require(recovered.get('healed') is True, 'Удалённое восстановление сети Docker не завершено')
                after = assert_baseline(nodes, args.multi_host_script,
                                        args.directory, args.project, edge)
                restore_success = bool(after)
            except (ChaosError, multi.DeploymentError, multi.inventory.InventoryError, OSError, ValueError):
                restore_success = False
        result['recoveredAndVerified'] = restore_success
        if not restore_success:
            result['status'] = 'FAIL'
            result['recoveryRequired'] = True
        result['completedUtc'] = utc()
        result['durationSeconds'] = round(time.monotonic() - start, 3)
        save_new(report, result)
        if restore_success:
            state_path.unlink()
            fsync_dir(state_path.parent)
        return result
    except BaseException:
        # Процесс, завершённый в небезопасном промежутке, оставляет устойчивый журнал
        # для явной операции recover. Успешный отчёт на этом пути не формируется.
        raise


def manual_recover(args, nodes):
    state_path = Path(args.state).absolute()
    state = read_state(state_path)
    require(state.get('project') == args.project and state.get('nodes') == nodes and
            state.get('failedNode') in nodes, 'Цель восстановления отличается от записанной операции')
    victim = state['failedNode']
    if state['fault'] == 'host-stop':
        multi.remote_stop_start(nodes[victim], args.multi_host_script, args.directory, args.project, 'start')
    elif state['fault'] == 'network-partition':
        response = ssh_helper(nodes[victim], args.chaos_script, args.directory,
                              args.project, 'local-heal')
        require(response.get('healed') is True, 'Ошибка удалённого восстановления сети')
    else:
        raise ChaosError('Неизвестный тип нарушения в журнале')
    assert_baseline(nodes, args.multi_host_script, args.directory, args.project,
                    endpoint_url(args.edge_url))
    state_path.unlink()
    fsync_dir(state_path.parent)
    return {'status': 'RECOVERED', 'restorationVerified': True}


def validate_node_urls(node_urls):
    records = {}
    for spec in node_urls:
        label, sep, url = spec.partition('=')
        require(sep and multi.LABEL_REGEX.fullmatch(label) and label not in records,
                'Повторяющийся или некорректный адрес проверки готовности узла по HTTPS')
        endpoint_url(url)
        records[label] = url.rstrip('/') + ('' if url.endswith('/ready') else '/ready')
    require(len(records) >= 2 and len(set(records.values())) == len(records),
            'Требуются как минимум два различных независимых URL проверки готовности узлов')
    return records


def render_monitor(args):
    targets = validate_node_urls(args.node_url)
    endpoint = endpoint_url(args.edge_url)
    edge = endpoint if endpoint.endswith('/ready') else endpoint + '/ready'
    # JSON является допустимым YAML и предотвращает случайную интерпретацию недоверенных
    # URL.
    rules = {'groups': [{'name': 'neverlauncher-multi-host-05110', 'rules': [
        {'alert': 'NeverLauncherHostIngressDown',
         'expr': 'probe_success{job="neverlauncher-host-ready-05110"} == 0 or up{job="neverlauncher-host-ready-05110"} == 0',
         'for': '30s', 'labels': {'severity': 'critical'},
         'annotations': {'summary': 'Проверка готовности входного узла многоузловой системы не пройдена'}},
        {'alert': 'NeverLauncherInsufficientHealthyHosts',
         'expr': 'sum(probe_success{job="neverlauncher-host-ready-05110"}) < 2 or absent(probe_success{job="neverlauncher-host-ready-05110"})',
         'for': '30s', 'labels': {'severity': 'critical'},
         'annotations': {'summary': 'Менее двух входных узлов исправны'}},
        {'alert': 'NeverLauncherPublicIngressDown',
         'expr': 'probe_success{job="neverlauncher-public-ready-05110"} == 0 or up{job="neverlauncher-public-ready-05110"} == 0',
         'for': '30s', 'labels': {'severity': 'critical'},
         'annotations': {'summary': 'Проверка готовности через публичный HTTPS не пройдена'}},
    ]}]}
    def probe_job(job, urls):
        return {'job_name': job, 'metrics_path': '/probe', 'params': {'module': ['https_2xx_strict']},
                'static_configs': [{'targets': [value], 'labels': {'node': name}}
                                   for name, value in sorted(urls.items())],
                'relabel_configs': [
                    {'source_labels': ['__address__'], 'target_label': '__param_target'},
                    {'source_labels': ['__param_target'], 'target_label': 'instance'},
                    {'target_label': '__address__', 'replacement': 'blackbox:9115'}]}
    monitor = {'global': {'scrape_interval': '10s', 'evaluation_interval': '10s'},
               'rule_files': ['/etc/prometheus/alerts.yml'],
               'alerting': {'alertmanagers': [{'static_configs': [{'targets': ['alertmanager:9093']}]}]},
               'scrape_configs': [probe_job('neverlauncher-host-ready-05110', targets),
                                  probe_job('neverlauncher-public-ready-05110', {'public': edge})]}
    output = Path(args.output_directory).absolute()
    require(output.is_dir() and not output.is_symlink(), 'Каталог вывода мониторинга должен существовать')
    require(all(not (output / name).exists() and not (output / name).is_symlink()
                for name in ('prometheus-05110.yml', 'alerts-05110.yml')),
            'Результат мониторинга уже существует; частичная перезапись запрещена')
    save_new(output / 'prometheus-05110.yml', monitor)
    save_new(output / 'alerts-05110.yml', rules)
    return {'status': 'GENERATED', 'targets': len(targets),
            'configFiles': ['prometheus-05110.yml', 'alerts-05110.yml']}


def run_suite(args, nodes):
    """Повторять оба реальных сценария отказа на каждом проверенном физическом Docker-хосте.

    Немедленно останавливаться после любой ошибки; не продолжать с невосстановленным узлом. Каждый
    сценарий имеет отдельное устойчивое намерение, подробные свидетельства и SHA-256 в сводке
    набора, чтобы другой оператор мог независимо изучить точные результаты.
    """
    home = Path(args.suite_directory).absolute()
    require(home.is_dir() and not home.is_symlink() and home.stat().st_uid == os.geteuid() and
            stat.S_IMODE(home.stat().st_mode) & 0o077 == 0,
            'Каталог набора проверок должен принадлежать оператору и иметь права 0700')
    require(1 <= args.iterations <= 3, 'Число повторов набора проверок должно быть от 1 до 3')
    require(not any(p.name != '.multi-host-chaos-05110.lock' for p in home.iterdir()),
            'Каталог набора проверок изначально должен быть пустым; смешивать свидетельства нельзя')
    summary = {'schema': SCHEMA, 'release': '0.51.10', 'status': 'FAILED',
               'startedUtc': utc(), 'iterations': args.iterations, 'cases': []}
    try:
        for iteration in range(args.iterations):
            for name in sorted(nodes):
                for fault in ('host-stop', 'network-partition'):
                    basename = f'{iteration+1:02d}-{name}-{fault}'
                    child = argparse.Namespace(**vars(args))
                    child.failed_node, child.fault = name, fault
                    child.state = str(home / (basename + '.state.json'))
                    child.report = str(home / (basename + '.report.json'))
                    result = run_fault(child, nodes)
                    receipt = Path(child.report).read_bytes()
                    summary['cases'].append({'node': name, 'fault': fault, 'iteration': iteration+1,
                        'status': result['status'], 'recovered': result.get('recoveredAndVerified') is True,
                        'reportFile': Path(child.report).name,
                        'sha256': hashlib.sha256(receipt).hexdigest()})
                    require(result['status'] == 'PASS' and result.get('recoveredAndVerified') is True,
                            'Набор проверок остановлен на неудачном или невосстановленном сценарии')
        summary['status'] = 'PASS'
    except (ChaosError, multi.DeploymentError, multi.inventory.InventoryError, OSError, ValueError):
        summary['status'] = 'FAIL'
    summary['completedUtc'] = utc()
    save_new(home / 'suite-report.json', summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    local = {}
    for mode in ('local-isolate', 'local-status', 'local-heal'):
        p = sub.add_parser(mode)
        p.add_argument('--directory', required=True)
        p.add_argument('--project', required=True)
        if mode == 'local-isolate':
            p.add_argument('--approval-file', required=True)
        local[mode] = p
    for mode in ('run', 'recover', 'suite'):
        p = sub.add_parser(mode)
        p.add_argument('--node', action='append', required=True)
        p.add_argument('--directory', required=True)
        p.add_argument('--project', required=True)
        p.add_argument('--multi-host-script', default='/opt/launcher/scripts/operations/multi_host_0512.py')
        p.add_argument('--chaos-script', default='/opt/launcher/scripts/operations/multi_host_chaos_05110.py')
        p.add_argument('--edge-url', required=True)
        if mode in ('run', 'recover'):
            p.add_argument('--state', required=True)
        if mode in ('run', 'suite'):
            if mode == 'run':
                p.add_argument('--failed-node', required=True)
                p.add_argument('--fault', choices=('host-stop', 'network-partition'), required=True)
                p.add_argument('--report', required=True)
            else:
                p.add_argument('--suite-directory', required=True)
                p.add_argument('--iterations', type=int, default=1)
            p.add_argument('--approval-file', default='/opt/launcher/deploy/production/.chaos-approval-05110.json')
            p.add_argument('--allow-disruption', required=True)
            p.add_argument('--timeout', type=int, default=90)
            p.add_argument('--alertmanager-url')
            p.add_argument('--alert-name', default='NeverLauncherHostIngressDown')
            p.add_argument('--alert-timeout', type=int, default=100)
    m = sub.add_parser('monitor-config')
    m.add_argument('--node-url', action='append', required=True)
    m.add_argument('--edge-url', required=True)
    m.add_argument('--output-directory', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode.startswith('local-'):
            require(multi.PROJECT_REGEX.fullmatch(args.project), 'Недопустимый проект')
            directory = Path(args.directory).absolute()
            if args.mode == 'local-isolate':
                result = local_isolate(directory, args.project, Path(args.approval_file).absolute())
            elif args.mode == 'local-status':
                result = local_status(directory, args.project)
            else:
                result = local_heal(directory, args.project)
        elif args.mode == 'monitor-config':
            result = render_monitor(args)
        else:
            nodes = multi.parse_nodes(args.node)
            require(multi.PROJECT_REGEX.fullmatch(args.project), 'Недопустимый проект')
            if args.mode == 'suite':
                suite_dir = Path(args.suite_directory).absolute()
                with lock_for(suite_dir):
                    result = run_suite(args, nodes)
            else:
                state = Path(args.state).absolute()
                with lock_for(state.parent):
                    if args.mode == 'run':
                        result = run_fault(args, nodes)
                    else:
                        result = manual_recover(args, nodes)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get('status') not in ('FAIL', 'FAILED') and result.get('healed') is not False else 2
    except (ChaosError, multi.DeploymentError, multi.inventory.InventoryError, OSError, ValueError, KeyError, TypeError) as exc:
        # Секреты, необработанный вывод Docker/SSH, URL и окружение никогда не
        # отправляются в stderr.
        print(json.dumps({'status': 'FAILED', 'reason': str(exc)[:160]}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

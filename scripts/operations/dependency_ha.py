#!/usr/bin/env python3
"""Граничный HAProxy/VRRP и отказоустойчивость зависимостей NeverLauncher 0.51.3.

Запускается на хосте балансировщика. Каждый из двух LB-хостов работает независимо с одинаковыми
upstream; unicast VRRP VIP переходит между ними. Для PostgreSQL используется Patroni /primary (не
просто открытый TCP), для Redis — аутентифицированная проверка TLS INFO основного узла репликации,
для S3 — эндпоинт здоровья с учётом кворума.

Репликация и fencing кластеров БД/Sentinel/хранилища этим прокси не реализуются: их НЕОБХОДИМО
отдельно настроить и протестировать.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import hmac
import http.client
import secrets
import ssl
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import time

import multi_host_0512 as multi
import ha_inventory_0511 as inventory

VERSION = '0.51.3'
SCHEMA = 'neverlauncher.dependency-ha.0.51.3'
NAME = re.compile(r'^[a-zA-Z][a-zA-Z0-9-]{0,62}$')
DNS = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$')
IFACE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_.:-]{0,20}$')

class HAError(Exception):
    pass


def secure_file(path: Path, secret=True):
    if not path.is_file() or path.is_symlink():
        raise HAError('Обязательный обычный файл отсутствует или является символической ссылкой: ' + path.name)
    if secret and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise HAError('Слишком широкие права доступа к закрытому файлу: ' + path.name)


def load_env(path):
    secure_file(path)
    config = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key) or key in config or '\x00' in value:
            raise HAError('Некорректная или повторяющаяся переменная окружения')
        # Никогда не исполняйте .env как программу оболочки.
        config[key] = value
    return config


def ipv4(value, label):
    try:
        address = ipaddress.ip_address(value)
        if address.version != 4 or address.is_loopback or address.is_multicast or address.is_unspecified:
            raise ValueError('Недопустимый для маршрутизации IPv4-адрес')
        return str(address)
    except ValueError as exc:
        raise HAError('invalid IP: ' + label) from exc


def port(value, label):
    try:
        n = int(value)
        if not 1 <= n <= 65535:
            raise ValueError()
        return n
    except (ValueError, TypeError) as exc:
        raise HAError('Некорректный порт: ' + label) from exc


def hostname(value, label):
    if not DNS.fullmatch(value) or value.startswith('-') or '..' in value:
        raise HAError('Некорректное имя хоста: ' + label)
    return value.lower()


def backends(env, key, count):
    # Формат NAME@IPv4:PORT, разделитель — запятая; никогда не передавать через
    # командную оболочку.
    result = []
    for entry in env.get(key, '').split(','):
        match = re.fullmatch(r'([a-zA-Z][a-zA-Z0-9-]{0,30})@([^:,]+):([0-9]{1,5})', entry.strip())
        if not match:
            raise HAError('Некорректный список серверов Backend: ' + key)
        name, address, p = match.groups()
        result.append((name, ipv4(address, key), port(p, key)))
    if len(result) < count or len({x[0] for x in result}) != len(result) or len({x[1] for x in result}) != len(result):
        raise HAError('Серверы Backend должны иметь разные имена и адреса: ' + key)
    return result


def validate(env):
    iface = env.get('HA_INTERFACE', '')
    if not IFACE.fullmatch(iface):
        raise HAError('Некорректный сетевой интерфейс VRRP')
    public = ipv4(env.get('HA_PUBLIC_VIP', ''), 'HA_PUBLIC_VIP')
    dependency = ipv4(env.get('HA_DEPENDENCY_VIP', ''), 'HA_DEPENDENCY_VIP')
    local = ipv4(env.get('HA_LB_LOCAL_IP', ''), 'HA_LB_LOCAL_IP')
    peer = ipv4(env.get('HA_LB_PEER_IP', ''), 'HA_LB_PEER_IP')
    if len({public, dependency, local, peer}) != 4:
        raise HAError('Виртуальные IP VRRP и два адреса балансировщиков должны различаться')
    prefix = int(env.get('HA_VIP_PREFIX', '24'))
    if not 16 <= prefix <= 30:
        raise HAError('Префикс виртуального IP должен находиться в диапазоне от /16 до /30')
    subnet = ipaddress.ip_network(public + '/' + str(prefix), strict=False)
    if any(ipaddress.ip_address(x) not in subnet for x in (public, dependency, local, peer)):
        raise HAError('Для VRRP адреса соседа, балансировщика и виртуальный IP должны находиться в одной подсети L2')
    priority = int(env.get('HA_PRIORITY', '0'))
    router = int(env.get('HA_VRRP_ID', '0'))
    if not 1 <= priority <= 254 or not 1 <= router <= 255:
        raise HAError('Приоритет VRRP или ID маршрутизатора вне допустимого диапазона')
    public_name = hostname(env.get('HA_PUBLIC_NAME', ''), 'HA_PUBLIC_NAME')
    redis_name = hostname(env.get('HA_REDIS_NAME', ''), 'HA_REDIS_NAME')
    s3_name = hostname(env.get('HA_S3_NAME', ''), 'HA_S3_NAME')
    if len({public_name, redis_name, s3_name}) != 3:
        raise HAError('Имена хостов TLS должны различаться')
    ca_path = Path(env.get('HA_CA_BUNDLE', '/etc/ssl/certs/ca-certificates.crt'))
    if not ca_path.is_absolute():
        raise HAError('Путь к набору сертификатов CA должен быть абсолютным')
    # Запрещены символы со специальным значением для парсера конфигурации
    # HAProxy.
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(ca_path)):
        raise HAError('Некорректный путь к набору сертификатов CA')
    health_path = env.get('HA_S3_HEALTH_PATH', '/minio/health/cluster')
    if not re.fullmatch(r'/[A-Za-z0-9/_-]{1,120}', health_path):
        raise HAError('Путь проверки состояния шлюза S3 должен быть абсолютным и не содержать параметров запроса')
    pg = backends(env, 'HA_POSTGRES', 2)
    redis = backends(env, 'HA_REDIS', 2)
    s3 = backends(env, 'HA_S3', 2)
    edge = backends(env, 'HA_INGRESS', 2)
    patroni_port = port(env.get('HA_PATRONI_PORT', '8008'), 'HA_PATRONI_PORT')
    redis_port = port(env.get('HA_REDIS_LISTEN_PORT', '6380'), 'HA_REDIS_LISTEN_PORT')
    user = env.get('HA_REDIS_HEALTH_USER', '')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', user):
        raise HAError('Необходимо указать пользователя для проверки состояния Redis')
    secret_path = Path(env.get('HA_REDIS_HEALTH_PASSWORD_FILE', ''))
    if not secret_path.is_absolute():
        raise HAError('Пароль для проверки Redis должен считываться из закрытого файла по абсолютному пути')
    secure_file(secret_path)
    password = secret_path.read_bytes().rstrip(b'\r\n')
    if not (16 <= len(password) <= 256) or b'\r' in password or b'\n' in password or b'\0' in password:
        raise HAError('Некорректные учётные данные проверки Redis')
    if env.get('HA_S3_SHARED_BACKEND_CONFIRMED') != 'yes':
        raise HAError('Шлюзы S3 должны обслуживать одно реплицируемое или защищённое кворумом пространство объектов')
    return dict(interface=iface, public=public, dep=dependency, local=local, peer=peer,
                prefix=prefix, priority=priority, router=router, public_name=public_name,
                redis_name=redis_name, s3_name=s3_name, ca=str(ca_path), health_path=health_path,
                patroni_port=patroni_port, redis_port=redis_port, user=user, password=password,
                postgres=pg, redis=redis, s3=s3, edge=edge)


def resp(*parts):
    seq = b'*' + str(len(parts)).encode() + b'\r\n'
    for part in parts:
        data = part if isinstance(part, bytes) else str(part).encode('utf-8')
        seq += b'$' + str(len(data)).encode() + b'\r\n' + data + b'\r\n'
    return seq.hex()


def generate_haproxy(cfg):
    ca = cfg['ca']
    public = cfg['public_name']
    redis = cfg['redis_name']
    s3 = cfg['s3_name']
    lines = [
        '# Generated from private config by dependency_ha_0513.py; mode 0600.',
        'global',
        '    log /dev/log local0',
        '    maxconn 20000',
        '    stats socket /run/haproxy/launcher-ha.sock mode 660 level operator',
        'defaults',
        '    log global',
        '    mode tcp',
        '    option dontlognull',
        '    timeout connect 4s',
        '    timeout client 300s',
        '    timeout server 300s',
        '    timeout check 4s',
        'frontend ingress_https',
        f"    bind {cfg['public']}:443",
        '    default_backend ingress_nodes',
        'frontend postgres_rw',
        f"    bind {cfg['dep']}:5432",
        '    default_backend postgres_primary',
        'frontend redis_tls',
        f"    bind {cfg['dep']}:{cfg['redis_port']}",
        '    default_backend redis_primary',
        'frontend s3_https',
        f"    bind {cfg['dep']}:443",
        '    default_backend s3_gateways',
        'backend ingress_nodes',
        '    balance leastconn',
        '    option httpchk',
        f'    http-check send meth GET uri /ready ver HTTP/1.1 hdr Host {public}',
        '    http-check expect status 200',
        '    default-server inter 2s fastinter 1s fall 2 rise 2',
    ]
    for name, ip, p in cfg['edge']:
        lines.append(f'    server {name} {ip}:{p} check check-ssl check-sni {public} verify required verifyhost {public} ca-file {ca}')
    lines.extend([
        'backend postgres_primary',
        '    option httpchk',
        '    http-check send meth GET uri /primary ver HTTP/1.1 hdr Host patroni',
        '    http-check expect status 200',
        '    default-server inter 2s fastinter 1s fall 2 rise 2 on-marked-down shutdown-sessions',
    ])
    for name, ip, p in cfg['postgres']:
        lines.append(f"    server {name} {ip}:{p} check port {cfg['patroni_port']}")
    lines.extend([
        'backend redis_primary',
        '    option tcp-check',
        f'    tcp-check connect ssl sni str({redis})',
        f"    tcp-check send-binary {resp('AUTH', cfg['user'], cfg['password'])}",
        '    tcp-check expect string +OK',
        f"    tcp-check send-binary {resp('INFO', 'replication')}",
        '    tcp-check expect rstring role:master',
        '    default-server inter 2s fastinter 1s fall 2 rise 2 on-marked-down shutdown-sessions',
    ])
    for name, ip, p in cfg['redis']:
        lines.append(f'    server {name} {ip}:{p} check check-ssl check-sni {redis} verify required verifyhost {redis} ca-file {ca}')
    lines.extend([
        'backend s3_gateways',
        '    balance leastconn',
        '    option httpchk',
        f"    http-check send meth GET uri {cfg['health_path']} ver HTTP/1.1 hdr Host {s3}",
        '    http-check expect status 200',
        '    default-server inter 2s fastinter 1s fall 2 rise 2',
    ])
    for name, ip, p in cfg['s3']:
        lines.append(f'    server {name} {ip}:{p} check check-ssl check-sni {s3} verify required verifyhost {s3} ca-file {ca}')
    return '\n'.join(lines) + '\n'


def generate_keepalived(cfg):
    # В файле нет секретов. VRRP ограничен явно выделенной частной доверенной сетью
    # управления одного уровня L2; защита от split-brain выходит за рамки VRRP.
    return f'''# NeverLauncher 0.51.3 ingress/dependency VIP. VRRP is NOT a quorum DCS.
global_defs {{
    enable_script_security
    script_user root
}}
vrrp_script launcher_haproxy {{
    script "/usr/bin/systemctl is-active --quiet haproxy"
    interval 2
    fall 2
    rise 2
    weight -80
}}
vrrp_instance LAUNCHER_HA {{
    state BACKUP
    interface {cfg['interface']}
    virtual_router_id {cfg['router']}
    priority {cfg['priority']}
    advert_int 1
    unicast_src_ip {cfg['local']}
    unicast_peer {{
        {cfg['peer']}
    }}
    virtual_ipaddress {{
        {cfg['public']}/{cfg['prefix']} dev {cfg['interface']}
        {cfg['dep']}/{cfg['prefix']} dev {cfg['interface']}
    }}
    track_script {{
        launcher_haproxy
    }}
}}
'''


def new_file(path, content, mode):
    # Никогда не перезаписывайте развёрнутую конфигурацию прокси и не следуйте по
    # символьной ссылке в пути.
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), mode)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content.encode('utf-8'))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def render(cfg, directory):
    if not directory.is_dir() or directory.is_symlink():
        raise HAError('Каталог вывода должен существовать и не быть символической ссылкой')
    outputs = {'haproxy.launcher-0513.cfg': generate_haproxy(cfg),
               'keepalived.launcher-0513.conf': generate_keepalived(cfg),
               '99-launcher-ha-nonlocal-bind.conf': 'net.ipv4.ip_nonlocal_bind = 1\n'}
    if any((directory / name).exists() or (directory / name).is_symlink() for name in outputs):
        raise HAError('Вывод уже существует; для каждого релиза выбирайте пустой каталог')
    written = []
    try:
        for name, content in outputs.items():
            path = directory / name
            new_file(path, content, 0o600 if name.startswith('haproxy') else 0o644)
            written.append(path)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    return {'files': [str(path) for path in written], 'configured': True}


def check_config(path):
    secure_file(path)
    multi.run(['haproxy', '-c', '-f', str(path)], timeout=12)
    return {'haproxySyntaxValid': True}


def stats(socket_path):
    # Читайте фактическое состояние работоспособности из Runtime HAProxy, а не
    # предположения по установлению TCP-соединения.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(4)
        s.connect(str(socket_path))
        s.sendall(b'show stat\n')
        data = bytearray()
        while len(data) < 262144:
            block = s.recv(8192)
            if not block:
                break
            data.extend(block)
    if len(data) >= 262144:
        raise HAError('Ответ HAProxy превышает лимит')
    decoded = data.decode('utf-8', 'replace').lstrip('# ').strip()
    rows = list(csv.DictReader(io.StringIO(decoded)))
    results = {}
    for row in rows:
        px, server = row.get('pxname'), row.get('svname')
        if px in ('ingress_nodes', 'postgres_primary', 'redis_primary', 's3_gateways') and server not in ('BACKEND', 'FRONTEND'):
            results.setdefault(px, {})[server] = row.get('status', '')
    return results


def health(stats_result, *, redundant=True):
    expected = {'ingress_nodes': 2, 'postgres_primary': 1,
                'redis_primary': 1, 's3_gateways': 2}
    issues = []
    counts = {}
    for backend, required in expected.items():
        nodes = stats_result.get(backend, {})
        up = [name for name, status in nodes.items() if status in ('UP', 'UP 1/2', 'UP 2/2')]
        counts[backend] = {'up': len(up), 'total': len(nodes), 'active': up}
        minimum = (required if redundant else 1)
        if len(up) < minimum:
            issues.append(backend + ' has insufficient live healthy endpoints')
        if backend in ('postgres_primary', 'redis_primary') and len(up) != 1:
            issues.append(backend + ' must have exactly one writable primary (split-brain or no leader)')
    return {'backends': counts, 'issues': issues, 'healthy': not issues,
            'scope': 'HAProxy live backend checks; not standalone proof of storage durability or upstream quorum'}


def probe_edge(url):
    ok, evidence = multi.edge_ready(url, count=3)
    return ok, {'sampled': evidence['sampled'], 'success': evidence['success']}


def cluster_ready(nodes, script, directory, project, edge_url):
    reports = multi.collect_cluster(nodes, script, directory, project, 'local-observe')
    result = multi.cluster_verify(reports, edge_url)
    return result['multiHostControlPlaneObserved'], {'ready': result['multiHostControlPlaneObserved'],
                                                     'issues': result['issues']}


def perform_verification(sock, edge_url, nodes, *, redundant, cfg=None, creds=None):
    observed = health(stats(sock), redundant=redundant)
    public_ok, public = probe_edge(edge_url)
    observed['publicEdge'] = public
    observed['healthy'] = observed['healthy'] and public_ok
    if cfg is not None and creds is not None:
        active = set(observed['backends']['s3_gateways']['active'])
        selected = [g for g in cfg['s3'] if g[0] in active]
        if not selected:
            raise HAError('Нет исправных шлюзов S3 для проверки записи и чтения подписанного объекта')
        proof = s3_object_probe(cfg, creds, selected)
        observed['s3CrossGatewayProbe'] = proof
        if redundant and not proof['crossGatewayReadBack']:
            observed['healthy'] = False
    if nodes:
        ok, state = cluster_ready(nodes, '/opt/launcher/scripts/operations/multi_host_0512.py',
                                  '/opt/launcher/deploy/production', 'launcher', edge_url)
        observed['applicationDependencyRoundTrips'] = state
        observed['healthy'] = observed['healthy'] and ok
    return observed


def systemd_ssh(host, service, verb):
    if not multi.HOST_REGEX.fullmatch(host) or host.startswith('-'):
        raise HAError('Недопустимый узел назначения SSH')
    if service not in ('patroni', 'redis-server', 'minio', 'haproxy') or verb not in ('stop', 'start'):
        raise HAError('Некорректная единица отказоустойчивого теста')
    # Никаких подстановок; закрепляйте ключи SSH хостов и запрещайте запросы
    # паролей.
    multi.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=8', '-o', 'NumberOfPasswordPrompts=0', host,
               'sudo -n systemctl ' + verb + ' ' + service], timeout=35)


def drill(sock, edge_url, nodes, service, server, target, deadline, cfg=None, creds=None):
    category = {'patroni': 'postgres_primary', 'redis-server': 'redis_primary',
                'minio': 's3_gateways', 'haproxy': 'ingress_nodes'}[service]
    initial = stats(sock)
    initial_health = health(initial, redundant=True)
    if not initial_health['healthy']:
        raise HAError('Перед моделированием отказа необходим исправный резервируемый контур')
    baseline = perform_verification(sock, edge_url, nodes, redundant=True, cfg=cfg, creds=creds)
    if not baseline['healthy']:
        raise HAError('Перед моделированием отказа приложение и хранилища данных должны быть исправны')
    if initial[category].get(server) != 'UP':
        raise HAError('Выбранный сервер Backend сейчас не находится в состоянии UP; тест переключения будет недостоверным')
    # Отключение реплики ещё не означает переключения первичного узла. Сначала
    # требуйте, чтобы именно проверяемая авторитетная служба владела ролью
    # активного лидера.
    before_active = health(initial, redundant=True)['backends'][category]['active']
    if service in ('patroni', 'redis-server') and before_active != [server]:
        raise HAError('Для проверки переключения БД или Redis необходимо вывести из строя действующий основной узел')
    # Не допускайте незаметного нарушения работы постороннего SSH-хоста. Имя
    # SSH-хоста должно разрешаться в настроенный адрес backend, нельзя доверять
    # одному утверждению пользователя.
    configured = cfg['postgres' if service == 'patroni' else
                     'redis' if service == 'redis-server' else 's3'] if cfg else []
    address = next((ip for name, ip, _ in configured if name == server), None)
    if address is None:
        raise HAError('Идентификатор Backend отсутствует в действующей конфигурации высокой доступности')
    # Для управляющего SSH часто используется отдельный внеполосный адрес. Проверяйте
    # НА УДАЛЁННОЙ ОС, что ей действительно принадлежит настроенный IP плоскости
    # данных. Равенство DNS некорректно для внеполосного управления и может
    # подделываться псевдонимами.
    try:
        raw = multi.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                         '-o', 'ConnectTimeout=8', '-o', 'NumberOfPasswordPrompts=0',
                         target, 'ip -j -4 addr show'], timeout=15)
        interface_list = json.loads(raw)
        observed = {item.get('local') for dev in interface_list
                    for item in dev.get('addr_info', [])
                    if item.get('family') == 'inet'}
    except (ValueError, TypeError, AttributeError, OSError, multi.DeploymentError) as exc:
        raise HAError('Не удалось независимо проверить сетевые интерфейсы Backend') from exc
    if address not in observed:
        raise HAError('Цель SSH не является настроенным физическим хостом Backend')
    # Нужно проверенное оператором соответствие имени backend и SSH-хоста. Никогда
    # не выбирайте случайную удалённую машину только по строке отчёта.
    stopped, checks, restored, outcome = False, [], False, False
    try:
        systemd_ssh(target, service, 'stop')
        stopped = True
        until = time.monotonic() + deadline
        while time.monotonic() < until:
            try:
                observation = perform_verification(sock, edge_url, nodes, redundant=False, cfg=cfg, creds=creds)
                selected = health(stats(sock), redundant=False)
                excluded = server not in selected['backends'][category]['active']
                checks.append({'healthy': observation['healthy'], 'stoppedBackendExcluded': excluded,
                               'active': selected['backends'][category]['active']})
                # Для служб с состоянием обязательна наблюдаемая смена лидера, а не просто
                # исключение остановленного узла балансировщиком.
                promoted = (service not in ('patroni', 'redis-server') or
                            (len(selected['backends'][category]['active']) == 1 and
                             selected['backends'][category]['active'][0] != server))
                checks[-1]['newLeaderObserved'] = promoted
                if observation['healthy'] and excluded and promoted:
                    outcome = True
                    break
            except (OSError, HAError, multi.DeploymentError, inventory.InventoryError):
                checks.append({'healthy': False})
            time.sleep(2)
    finally:
        try:
            systemd_ssh(target, service, 'start')
            restored = True
        except (HAError, multi.DeploymentError):
            restored = False
    recovery_observed = False
    if restored and outcome:
        until = time.monotonic() + deadline
        while time.monotonic() < until:
            try:
                recovered = perform_verification(sock, edge_url, nodes, redundant=True, cfg=cfg, creds=creds)
                if recovered['healthy']:
                    recovery_observed = True
                    break
            except (OSError, HAError, multi.DeploymentError, inventory.InventoryError):
                pass
            time.sleep(2)
    return {'schema': SCHEMA, 'version': VERSION, 'service': service, 'backend': server,
            'stopExecuted': stopped, 'restartCommandSucceeded': restored,
            'restorationReadinessObserved': recovery_observed,
            'observations': checks, 'failoverObserved': outcome,
            'testPassed': bool(stopped and restored and outcome and recovery_observed),
            'limitation': 'stops one systemd service, not physical host; validate actual PG/Redis leader promotion and S3 replication separately'}



def storage_credentials(env):
    """Читать закрытые учётные данные S3 с узким префиксом только непосредственно при проверке."""
    bucket = env.get('HA_S3_BUCKET', '')
    region = env.get('HA_S3_REGION', '')
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,62}', bucket) or not re.fullmatch(r'[a-z0-9-]{2,40}', region):
        raise HAError('Для проверки записи и чтения S3 необходимо указать бакет и регион')
    def read_secret(key):
        path = Path(env.get(key, ''))
        if not path.is_absolute():
            raise HAError('Учётные данные проверки S3 должны храниться в закрытом файле по абсолютному пути')
        secure_file(path)
        return path.read_text('utf-8').strip()
    access = read_secret('HA_S3_ACCESS_KEY_FILE')
    secret = read_secret('HA_S3_SECRET_KEY_FILE')
    if not 8 <= len(access) <= 256 or not 16 <= len(secret) <= 256 or not access.isascii() or not secret.isascii():
        raise HAError('Некорректные учётные данные проверки S3')
    token = ''
    if env.get('HA_S3_SESSION_TOKEN_FILE'):
        token = read_secret('HA_S3_SESSION_TOKEN_FILE')
    return {'bucket': bucket, 'region': region, 'access': access, 'secret': secret, 'token': token}


def signature(key, message):
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()


def aws_sigv4(method, path, host, payload, creds, now=None):
    """Заголовки AWS SigV4 для одного ограниченного запроса проверки S3 в режиме path-style."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    short = now.strftime('%Y%m%d')
    hashed = hashlib.sha256(payload).hexdigest()
    headers = {'Host': host, 'x-amz-date': amz_date, 'x-amz-content-sha256': hashed}
    if creds['token']:
        headers['x-amz-security-token'] = creds['token']
    names = sorted(k.lower() for k in headers)
    normalized = {k.lower(): v.strip() for k, v in headers.items()}
    canonical_headers = ''.join(k + ':' + normalized[k] + '\n' for k in names)
    scope = short + '/' + creds['region'] + '/s3/aws4_request'
    request = '\n'.join([method, path, '', canonical_headers, ';'.join(names), hashed])
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope,
                            hashlib.sha256(request.encode()).hexdigest()])
    key = signature(('AWS4' + creds['secret']).encode(), short)
    key = signature(key, creds['region'])
    key = signature(key, 's3')
    key = signature(key, 'aws4_request')
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = ('AWS4-HMAC-SHA256 Credential=' + creds['access'] + '/' + scope +
                                ', SignedHeaders=' + ';'.join(names) + ', Signature=' + sig)
    return headers


class PinnedHTTPS(http.client.HTTPSConnection):
    """Прямой IP шлюза, постоянный SNI/Host и реальная проверка TLS через системное хранилище доверия."""
    def __init__(self, hostname, address, port, ca):
        self.address = address
        super().__init__(hostname, port=port, timeout=8,
                         context=ssl.create_default_context(cafile=ca))

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def s3_request(cfg, creds, gateway, method, key, payload=b''):
    # Доказательства без секретов никогда не включают имена бакетов и объектов или
    # тела ответов.
    name, address, port_number = gateway
    path = '/' + creds['bucket'] + '/' + key
    headers = aws_sigv4(method, path, cfg['s3_name'], payload, creds)
    conn = PinnedHTTPS(cfg['s3_name'], address, port_number, cfg['ca'])
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            raise HAError('Ответ проверки S3 слишком велик')
        return response.status, body
    finally:
        conn.close()


def s3_object_probe(cfg, creds, gateways):
    """Записать через шлюз A, прочитать через B и наоборот; проверить удаление.

    Успешный HEAD на каждом шлюзе не доказывает общее пространство имён бакета. Подписанная
    межшлюзовая проверка записи/чтения/удаления может подтвердить его для данного наблюдения.
    """
    if not gateways:
        raise HAError('no live S3 gateway to probe')
    token = secrets.token_hex(16)
    key = 'launcher-ha-probe-0513/' + token
    payload = secrets.token_bytes(96)
    out = []
    try:
        for source in gateways:
            status, _ = s3_request(cfg, creds, source, 'PUT', key, payload)
            if status not in (200, 201, 204):
                raise HAError('Подписанный запрос PUT проверки S3 отклонён')
            for destination in gateways:
                status, observed = s3_request(cfg, creds, destination, 'GET', key)
                if status != 200 or observed != payload:
                    raise HAError('Чтение S3 через другой шлюз не совпало с подтверждённой записью')
            out.append(source[0])
        return {'passed': True, 'gateways': out, 'crossGatewayReadBack': len(gateways) > 1}
    finally:
        # Неудачное чтение или запись всё же могли зафиксироваться; удаляйте объект
        # из каждого работающего шлюза. Не превращайте неудачное удаление в неявный
        # PASS.
        errors = []
        for gateway in gateways:
            try:
                status, _ = s3_request(cfg, creds, gateway, 'DELETE', key)
                if status not in (200, 202, 204, 404):
                    errors.append(gateway[0])
            except (OSError, ssl.SSLError, HAError):
                errors.append(gateway[0])
        if errors:
            raise HAError('Не удалось очистить тестовые объекты S3; оператор должен найти их вручную')


def local_owns_vip(vip, interface):
    raw = multi.run(['ip', '-j', '-4', 'addr', 'show', 'dev', interface], timeout=8)
    try:
        data = json.loads(raw)
        return any(info.get('local') == vip for dev in data for info in dev.get('addr_info', []))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HAError('Не удалось проверить фактического владельца локального виртуального IP') from exc


def remote_owns_vip(target, vip, interface):
    if not multi.HOST_REGEX.fullmatch(target) or target.startswith('-'):
        raise HAError('Недопустимый узел назначения SSH')
    output = multi.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                        '-o', 'ConnectTimeout=8', target,
                        shlex.join(['ip', '-j', '-4', 'addr', 'show', 'dev', interface])], timeout=15)
    try:
        data = json.loads(output)
        return any(info.get('local') == vip for dev in data for info in dev.get('addr_info', []))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HAError('Не удалось проверить владельца удалённого виртуального IP') from exc


def edge_drill(sock, edge_url, nodes, cfg, target, deadline):
    """Выполнять на резервном балансировщике: остановить HAProxy активного узла и наблюдать реальный перенос VIP."""
    initial = health(stats(sock), redundant=True)
    if not initial['healthy']:
        raise HAError('Требуется исправный резервируемый контур Backend')
    if local_owns_vip(cfg['public'], cfg['interface']) or not remote_owns_vip(target, cfg['public'], cfg['interface']):
        raise HAError('Проверку пограничного узла нужно начинать на резервном узле, пока целевой узел владеет публичным VIP')
    stopped, restored, moved, checks = False, False, False, []
    try:
        systemd_ssh(target, 'haproxy', 'stop')
        stopped = True
        until = time.monotonic() + deadline
        while time.monotonic() < until:
            vip_here = local_owns_vip(cfg['public'], cfg['interface']) and local_owns_vip(cfg['dep'], cfg['interface'])
            edge_ok, _ = probe_edge(edge_url)
            gateway_health = health(stats(sock), redundant=False)['healthy']
            app_ok = True
            if nodes:
                app_ok, _ = cluster_ready(nodes,
                    '/opt/launcher/scripts/operations/multi_host_0512.py',
                    '/opt/launcher/deploy/production', 'launcher', edge_url)
            checks.append({'publicAndDependencyVIPMoved': vip_here, 'edgeReady': edge_ok,
                           'dependencyRoutingHealthy': gateway_health, 'applicationReady': app_ok})
            if vip_here and edge_ok and gateway_health and app_ok:
                moved = True
                break
            time.sleep(2)
    finally:
        try:
            systemd_ssh(target, 'haproxy', 'start')
            restored = True
        except (HAError, multi.DeploymentError):
            restored = False
    recovery_observed = False
    if stopped and restored and moved:
        until = time.monotonic() + deadline
        while time.monotonic() < until:
            ok, _ = probe_edge(edge_url)
            if ok and health(stats(sock), redundant=True)['healthy']:
                recovery_observed = True
                break
            time.sleep(2)
    return {'schema': SCHEMA, 'version': VERSION, 'scenario': 'VRRP active LB outage',
            'disrupted': stopped, 'restartCommandSucceeded': restored,
            'vipTransferredToSurvivor': moved, 'restorationReadinessObserved': recovery_observed,
            'observations': checks, 'testPassed': stopped and restored and moved and recovery_observed,
            'limitation': 'VRRP unicast failover, NOT split-brain fencing or upstream durable quorum'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('render', 'check', 'verify', 'drill', 'edge-drill'))
    parser.add_argument('--env-file', default='/etc/launcher/ha-0513.env')
    parser.add_argument('--output-dir')
    parser.add_argument('--haproxy-config', default='/etc/haproxy/haproxy.cfg')
    parser.add_argument('--socket', default='/run/haproxy/launcher-ha.sock')
    parser.add_argument('--edge-url')
    parser.add_argument('--node', action='append', default=[])
    parser.add_argument('--service', choices=('patroni', 'redis-server', 'minio', 'haproxy'))
    parser.add_argument('--backend-server')
    parser.add_argument('--target')
    parser.add_argument('--deadline', type=int, default=90)
    parser.add_argument('--allow-disruption', action='store_true')
    parser.add_argument('--output', help="Новый закрытый файл JSON-отчёта или -")
    args = parser.parse_args(argv)
    try:
        if args.mode == 'render':
            if not args.output_dir:
                raise HAError('Необходимо указать --output-dir')
            cfg = validate(load_env(Path(args.env_file)))
            report = render(cfg, Path(args.output_dir))
        elif args.mode == 'check':
            report = check_config(Path(args.haproxy_config))
        else:
            if not args.edge_url:
                raise HAError('Необходимо указать --edge-url')
            multi.validate_edge_url(args.edge_url)
            if args.deadline < 10 or args.deadline > 600:
                raise HAError('Время ожидания должно составлять от 10 до 600 секунд')
            nodes = multi.parse_nodes(args.node) if args.node else {}
            config = validate(load_env(Path(args.env_file)))
            creds = storage_credentials(load_env(Path(args.env_file)))
            if args.mode == 'verify':
                report = perform_verification(Path(args.socket), args.edge_url, nodes,
                                              redundant=True, cfg=config, creds=creds)
            elif args.mode == 'edge-drill':
                if not args.allow_disruption or not args.target:
                    raise HAError('Для edge-drill требуются --allow-disruption и --target')
                before = perform_verification(Path(args.socket), args.edge_url, nodes,
                                              redundant=True, cfg=config, creds=creds)
                if not before['healthy']:
                    raise HAError('Исходное состояние для проверки пограничного узла неисправно')
                report = edge_drill(Path(args.socket), args.edge_url, nodes, config,
                                    args.target, args.deadline)
            else:
                if not (args.allow_disruption and args.service and args.backend_server and args.target):
                    raise HAError('Для проверки требуются --allow-disruption --service --backend-server --target')
                if args.service == 'haproxy':
                    raise HAError('Отказ хоста HAProxy проверяется через edge-drill, а не через backend drill')
                if not NAME.fullmatch(args.backend_server):
                    raise HAError('Некорректное имя сервера Backend')
                report = drill(Path(args.socket), args.edge_url, nodes, args.service,
                               args.backend_server, args.target, args.deadline, config, creds)
        if args.output:
            inventory.write_report(args.output, report)
        elif args.mode != 'render':
            raise HAError('Для закрытого отчёта о результатах требуется --output')
        return 0 if report.get('healthy', report.get('testPassed', report.get('configured', report.get('haproxySyntaxValid', False)))) else 3
    except (HAError, multi.DeploymentError, inventory.InventoryError, OSError, ValueError) as exc:
        # Намеренно не выводите необработанную конфигурацию и закрытые учётные
        # данные.
        print('dependency HA operation unavailable: ' + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())

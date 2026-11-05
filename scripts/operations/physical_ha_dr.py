#!/usr/bin/env python3
"""Проводить физические эксперименты HA/DR 0.52.10, а НЕ симуляции только на Docker.

Запускать с независимого Linux-наблюдателя на одноразовом оборудовании HA. Блокировать при
расхождениях BMC, маршрутизатора, получателя оповещений, уцелевших хостов или восстановленного мира.
До физических изменений записывать их в журнал; восстановление через `heal`.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

import multi_host_0512 as multi
import multi_host_chaos_05110 as chaos
import dependency_ha_0513 as dependency
import dr_03512 as dr

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/acceptance'))
import vanilla_sidecar_live_0529 as vanilla

VERSION = (ROOT / 'VERSION').read_text().strip()
SCHEMA = 'neverlauncher.physical-ha-dr/0.52.10'
HEX = re.compile(r'[0-9a-f]{64}\Z')
SERIAL = re.compile(r'[A-Za-z0-9_.:-]{4,100}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')

class Blocked(RuntimeError):
    pass

def require(ok, why):
    if not ok:
        raise Blocked(why)

def now():
    return datetime.now(timezone.utc).isoformat()

def private_bytes(p, limit=8192):
    p = Path(p)
    require(p.is_absolute() and not p.is_symlink() and
            not any(parent.is_symlink() for parent in p.parents),
            'private file must have no symlinked ancestors')
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                (stat.S_IMODE(st.st_mode) & 0o077) == 0 and 0 < st.st_size <= limit,
                'unsafe private file metadata')
        raw = os.read(fd, limit + 1)
        require(len(raw) == st.st_size, 'private file changed during reading')
        return raw
    finally:
        os.close(fd)

def read_json(p):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, 'Повторяющееся поле объекта JSON')
            result[k] = v
        return result
    return json.loads(private_bytes(Path(p), 4 << 20), object_pairs_hook=unique)

def save(path, doc):
    # Журнал восстановления всегда создаётся до изменения состояния BMC или брандмауэра.
    path = Path(path)
    require(path.is_absolute() and path.parent.is_dir() and
            not path.parent.is_symlink() and path.parent.stat().st_uid == os.geteuid() and
            stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0,
            'private 0700 state parent required')
    payload = (json.dumps(doc, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def output(args, report):
    save(args.report, report)
    return 0 if report['status'] == 'PASS' else 3

def invoke(args, timeout=20, allow_fail=False):
    try:
        cp = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        if allow_fail:
            return None
        raise Blocked('Удалённое управление недоступно')
    require(len(cp.stdout) < 256_000, 'remote output too large')
    if cp.returncode and not allow_fail:
        raise Blocked('Удалённая команда отклонена')
    return cp.stdout.decode('utf-8', 'strict') if cp.returncode == 0 else None

def ssh(target, command, timeout=20, allow_fail=False):
    require(multi.HOST_REGEX.fullmatch(target) and not target.startswith('-'), 'invalid SSH host')
    return invoke(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'NumberOfPasswordPrompts=0', '-o', 'ConnectTimeout=5',
                   target, shlex.join(command)], timeout, allow_fail)

def redfish_parts(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and
            not parsed.password and not parsed.query and not parsed.fragment and
            re.fullmatch(r'/redfish/v1/Systems/[A-Za-z0-9_.-]+', parsed.path or ''),
            'Redfish must use a pinned HTTPS ComputerSystem resource')
    require(parsed.hostname.lower() not in ('localhost', '127.0.0.1', '::1'),
            'BMC cannot be loopback')
    return parsed

def redfish(url, token_path, ca, method='GET', body=None):
    parts = redfish_parts(url)
    raw_token = private_bytes(Path(token_path), 4096).strip()
    require(16 <= len(raw_token) <= 4096 and b'\n' not in raw_token and
            all(33 <= n <= 126 for n in raw_token), 'invalid BMC token')
    require(Path(ca).is_absolute() and Path(ca).is_file(), 'pinned BMC CA required')
    ctx = ssl.create_default_context(cafile=ca)
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=ctx, timeout=12)
    path = parts.path + ('/Actions/ComputerSystem.Reset' if method == 'POST' else '')
    headers = {'X-Auth-Token': raw_token.decode('ascii'), 'Accept': 'application/json',
               'Content-Type': 'application/json'}
    try:
        connection.request(method, path, body=json.dumps(body).encode() if body else None, headers=headers)
        response = connection.getresponse()
        raw = response.read(131073)
        require(len(raw) <= 131072, 'BMC response oversized')
        if method == 'POST':
            require(response.status in (200, 202, 204), 'BMC rejected power transition')
            return {'accepted': True}
        require(response.status == 200, 'BMC status rejected')
        result = json.loads(raw)
        require(isinstance(result, dict) and result.get('PowerState') in ('On', 'Off', 'PoweringOn', 'PoweringOff'),
                'BMC returned no verifiable physical power state')
        return result
    finally:
        connection.close()

def bmc_status(args):
    result = redfish(args.redfish_url, args.bmc_token_file, args.bmc_ca)
    require(result.get('SerialNumber') == args.expected_serial and
            SERIAL.fullmatch(args.expected_serial or ''),
            'BMC system serial does not match the approved physical host')
    return result

def bmc_reset(args, action):
    require(action in ('ForceOff', 'On'), 'unsupported Redfish reset')
    result = bmc_status(args)
    allowable = ((result.get('Actions') or {}).get('#ComputerSystem.Reset') or {}).get('ResetType@Redfish.AllowableValues')
    require(isinstance(allowable, list) and action in allowable,
            'BMC does not advertise requested reset capability')
    return redfish(args.redfish_url, args.bmc_token_file, args.bmc_ca,
                   'POST', {'ResetType': action})

def await_power(args, expected, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if bmc_status(args).get('PowerState') == expected:
            return True
        time.sleep(2)
    return False

def baseline(args, nodes):
    reports = multi.collect_cluster(nodes, args.remote_script, args.directory, args.project,
                                    'local-observe')
    result = multi.cluster_verify(reports, args.edge_url)
    require(result['multiHostControlPlaneObserved'] and len(reports) >= 2,
            'real multi-host baseline not healthy')
    ids = [v.get('machineIdentity') for v in reports.values()]
    require(len(set(ids)) == len(ids) and all(isinstance(x, str) and x for x in ids),
            'not distinct physical host identities')
    return reports

def survivor(args, nodes, victim):
    remaining = {k: v for k, v in nodes.items() if k != victim}
    observations, result = chaos.edge_survivor_probe(nodes, victim, args.remote_script,
         args.directory, args.project, args.edge_url, args.timeout, interval=1)
    require(result and all(result.values()) and len(observations) >= 8,
            'surviving hosts failed under a real physical disruption')
    return {'edgeSamples': observations, 'survivors': result}

def peer_connectivity(args, nodes, victim):
    # Проверяйте реальное TCP-подключение приложения с выживших узлов, а не административный SSH.
    require(1 <= args.victim_port <= 65535, 'invalid victim application TCP port')
    ip = ipaddress.ip_address(args.victim_ip)
    require(ip.version == 4 and ip.is_private, 'victim service address must be private IPv4')
    code = ('import socket,sys; '
            's=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3); s.close()')
    result = {}
    for name, target in nodes.items():
        if name != victim:
            result[name] = ssh(target, ['python3', '-c', code, str(ip), str(args.victim_port)],
                               timeout=10, allow_fail=True) is not None
    require(result, 'surviving application hosts missing')
    return result


def firewall(args, action):
    # Утверждённый выделенный маршрутизатор имеет заранее установленную политику nft в цепочке forward со
    # ссылкой на динамический набор с тайм-аутом. Произвольные правила сети и фрагменты удалённых shell-команд
    # запрещены. По истечении срока доступ восстанавливается даже при отказе наблюдателя.
    ip = ipaddress.ip_address(args.victim_ip)
    require(ip.version == 4 and ip.is_private and not ip.is_loopback and
            not ip.is_multicast and not ip.is_unspecified, 'invalid private victim IPv4')
    require(action in ('add', 'delete', 'check'), 'invalid firewall action')
    fixed = ['sudo', '-n', 'nft']
    policy = json.loads(ssh(args.router, fixed + ['-j', 'list', 'table', 'inet',
                         'launcher_partition_05210']))
    entries = policy.get('nftables', [])
    forwarding = [e['chain'] for e in entries if isinstance(e, dict) and 'chain' in e
                  and e['chain'].get('name') == 'forwarding']
    rules = [e['rule'] for e in entries if isinstance(e, dict) and 'rule' in e
             and e['rule'].get('chain') == 'forwarding']
    sets = [e['set'] for e in entries if isinstance(e, dict) and 'set' in e
            and e['set'].get('name') == 'victims4']
    def matches(rule, field):
        expr = rule.get('expr', [])
        return (any(isinstance(op, dict) and 'drop' in op for op in expr) and
                any(isinstance(op, dict) and isinstance(op.get('match'), dict) and
                    ((op['match'].get('left') or {}).get('payload') or {}).get('field') == field and
                    (op['match'].get('right') in ('@victims4', 'victims4') if
                     isinstance(op['match'].get('right'), str) else
                     isinstance(op['match'].get('right'), dict) and
                     op['match']['right'].get('set') in ('victims4', '@victims4'))
                    for op in expr))
    require(len(forwarding) == len(sets) == 1 and forwarding[0].get('hook') == 'forward'
            and 'timeout' in sets[0].get('flags', []) and len(rules) == 2 and
            any(matches(r, 'saddr') for r in rules) and any(matches(r, 'daddr') for r in rules),
            'unverified dedicated forwarding policy/expiry; no network injection permitted')
    if action == 'add':
        cmd = fixed + ['add', 'element', 'inet', 'launcher_partition_05210', 'victims4',
                       '{', str(ip), 'timeout', str(args.ttl) + 's', '}']
        ssh(args.router, cmd)
    elif action == 'delete':
        cmd = fixed + ['delete', 'element', 'inet', 'launcher_partition_05210', 'victims4',
                       '{', str(ip), '}']
        ssh(args.router, cmd)
    raw = ssh(args.router, fixed + ['-j', 'list', 'set', 'inet', 'launcher_partition_05210', 'victims4'])
    data = json.loads(raw)
    require(isinstance(data, dict) and isinstance(data.get('nftables'), list), 'router nftables status absent')
    # Это наблюдение членства; внешнее тестирование клиента подтверждает, проходит ли трафик действительно
    # через данный маршрутизатор.
    def element_address(entry):
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            nested = entry.get('elem', entry)
            if isinstance(nested, str):
                return nested
            if isinstance(nested, dict):
                return nested.get('val')
        return None
    present = any(isinstance(item, dict) and 'set' in item and
        any(str(ip) == element_address(e) for e in (item['set'].get('elem') or []))
        for item in data['nftables'])
    return present

def alert_delivery(args, started):
    # Одного состояния Alertmanager недостаточно. Отдельный нижестоящий HTTPS-получатель должен подтвердить
    # соответствующее активное событие после нарушения.
    require(bool(args.alertmanager_url and args.delivery_url), 'alert manager and downstream delivery URL required')
    base = urlsplit(args.alertmanager_url)
    target = urlsplit(args.delivery_url)
    require(base.scheme == target.scheme == 'https' and base.hostname and target.hostname
            and base.hostname != target.hostname and base.path in ('', '/') and
            target.path == '/events/latest' and not base.query and not base.fragment and
            not target.query and not target.fragment and
            not base.username and not target.username and not base.password and not target.password,
            'alerts and downstream receipt must be separate verified HTTPS hosts')
    require(args.alert_name and re.fullmatch(r'NeverLauncher[A-Za-z0-9]{2,80}', args.alert_name),
            'explicit expected alert name required')
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    token = private_bytes(Path(args.delivery_token_file), 4096).strip()
    require(len(token) >= 32 and all(33 <= n <= 126 for n in token),
            'independent alert receiver bearer token required')
    until = time.monotonic() + args.timeout
    while time.monotonic() < until:
        try:
            def load(url):
                request = urllib.request.Request(url, headers={
                    'Authorization': 'Bearer ' + token.decode('ascii')
                    } if url == args.delivery_url else {})
                with opener.open(request, timeout=7) as response:
                    raw = response.read(65537)
                require(len(raw) <= 65536, 'alert receipt too large')
                return json.loads(raw)
            entries = load(args.alertmanager_url.rstrip('/') + '/api/v2/alerts')
            receipt = load(args.delivery_url)
            if isinstance(entries, list) and isinstance(receipt, dict):
                for entry in entries:
                    if not isinstance(entry, dict) or (entry.get('labels') or {}).get('alertname') != args.alert_name or (entry.get('status') or {}).get('state') != 'active':
                        continue
                    stamp = datetime.fromisoformat(entry['startsAt'].replace('Z', '+00:00'))
                    delivery = datetime.fromisoformat(receipt['receivedAt'].replace('Z', '+00:00'))
                    if (stamp >= started and delivery >= stamp and
                            receipt.get('fingerprint') == entry.get('fingerprint') and
                            receipt.get('alertname') == args.alert_name and receipt.get('status') == 'delivered'):
                        return {'alertname': args.alert_name, 'fingerprint': entry['fingerprint'],
                                'deliveredAt': delivery.isoformat()}
        except (OSError, ValueError, TypeError, KeyError, Blocked):
            pass
        time.sleep(2)
    raise Blocked('Не обнаружено фактической внешней доставки оповещений')

def live_fault(args):
    nodes = multi.parse_nodes(args.node)
    require(args.victim in nodes and len(nodes) >= 2 and
            args.allow_disruption == 'I-ACCEPT-PHYSICAL-OUTAGE' and
            25 <= args.timeout <= 300, 'physical fault requires explicit bounded approval')
    require(not Path(args.state).exists() and not Path(args.state).is_symlink() and
            not Path(args.report).exists() and not Path(args.report).is_symlink(),
            'unrecovered prior journal/report')
    baseline(args, nodes)
    if args.mode == 'host':
        require(bmc_status(args).get('PowerState') == 'On', 'victim is not powered on')
    else:
        require(args.timeout + 45 <= args.ttl <= 600 and args.router not in nodes.values(),
                'router expiry must outlast observation window but remain bounded')
        require(not firewall(args, 'check'), 'victim still partitioned from earlier drill')
        require(bmc_status(args).get('PowerState') == 'On', 'partition requires powered-on target')
    require(ssh(nodes[args.victim], ['hostname'], allow_fail=True) is not None,
            'victim is not SSH reachable before physical fault')
    if args.mode == 'partition':
        require(all(peer_connectivity(args, nodes, args.victim).values()),
                'survivors cannot reach victim service before partition')
    fault_started = datetime.now(timezone.utc)
    save(args.state, {'schema': SCHEMA, 'mode': args.mode, 'phase': 'disruption-pending',
                      'victim': args.victim, 'victimTarget': nodes[args.victim],
                      'startedAt': fault_started.isoformat(), 'recoveryRequired': True,
                      'bmcUrl': args.redfish_url if args.mode == 'host' else None,
                      'victimIpv4': args.victim_ip if args.mode == 'partition' else None,
                      'automaticRouterExpirySeconds': args.ttl if args.mode == 'partition' else None})
    injected = False
    restored = False
    observations = {}
    try:
        if args.mode == 'host':
            bmc_reset(args, 'ForceOff')
            injected = await_power(args, 'Off', min(args.timeout, 90))
        else:
            injected = firewall(args, 'add')
        require(injected, 'physical fault was not observed')
        if args.mode == 'host':
            require(ssh(nodes[args.victim], ['hostname'], allow_fail=True) is None,
                    'powered-off host remains reachable via management SSH')
        else:
            require(bmc_status(args).get('PowerState') == 'On' and
                    ssh(nodes[args.victim], ['hostname'], allow_fail=True) is not None,
                    'network-only outage not proven: BMC or management unavailable')
            observations['partitionedPeerTcp'] = peer_connectivity(args, nodes, args.victim)
            require(not any(observations['partitionedPeerTcp'].values()),
                    'real peer data-plane traffic was not partitioned')
        observations.update(survivor(args, nodes, args.victim))
        observations['alert'] = alert_delivery(args, fault_started)
    finally:
        try:
            if args.mode == 'host':
                if bmc_status(args).get('PowerState') == 'Off':
                    bmc_reset(args, 'On')
                restored = await_power(args, 'On', max(args.timeout, 90))
            else:
                if firewall(args, 'check'):
                    firewall(args, 'delete')
                restored = not firewall(args, 'check')
        except (Blocked, OSError, ValueError):
            restored = False
    if restored and args.mode == 'partition':
        try:
            restored = all(peer_connectivity(args, nodes, args.victim).values())
        except (Blocked, multi.DeploymentError):
            restored = False
    if restored:
        until = time.monotonic() + args.timeout
        while time.monotonic() < until:
            try:
                baseline(args, nodes)
                observations['clusterRecovered'] = True
                break
            except (Blocked, multi.DeploymentError):
                time.sleep(3)
    passed = injected and restored and observations.get('clusterRecovered') is True and bool(observations.get('alert'))
    receipt = {'schema': SCHEMA, 'version': VERSION, 'mode': args.mode,
               'status': 'PASS' if passed else 'BLOCKED', 'faultObserved': injected,
               'physicalRecoveryObserved': restored, 'evidence': observations,
               'startedAt': fault_started.isoformat(), 'endedAt': now()}
    if passed:
        # Успешное восстановление, независимо подтверждённое повторно, закрывает журнал.
        Path(args.state).unlink()
    return output(args, receipt)

def heal(args):
    journal = read_json(args.state)
    require(journal.get('schema') == SCHEMA and journal.get('recoveryRequired') is True,
            'invalid recovery journal')
    require(journal.get('mode') == args.heal_mode,
            'recovery journal belongs to another fault type')
    if args.heal_mode == 'dependency':
        require(args.target == journal.get('target') and args.service == journal.get('service')
                and args.backend_server == journal.get('backend'),
                'dependency recovery target/service does not match durable journal')
        require(ssh(args.target, ['systemctl', 'is-active', args.service]).strip() == 'active',
                'dependency service not actually running')
        cfg = dependency.validate(dependency.load_env(Path(args.ha_env_file)))
        creds = dependency.storage_credentials(dependency.load_env(Path(args.ha_env_file)))
        multi.validate_edge_url(args.edge_url)
        report = dependency.perform_verification(Path(args.ha_socket), args.edge_url, {},
                                                redundant=True, cfg=cfg, creds=creds)
        require(report['healthy'], 'dependency quorum and ingress not recovered')
        Path(args.state).unlink()
        return 0
    require(journal.get('victim') == args.victim,
            'recovery journal belongs to another physical host')
    if args.heal_mode == 'host':
        require(journal.get('bmcUrl') == args.redfish_url, 'BMC recovery identity differs')
        state = bmc_status(args).get('PowerState')
        if state == 'Off':
            bmc_reset(args, 'On')
        ok = await_power(args, 'On', 120)
    else:
        require(journal.get('victimIpv4') == args.victim_ip, 'partition identity differs')
        if firewall(args, 'check'):
            firewall(args, 'delete')
        ok = not firewall(args, 'check')
    require(ok, 'physical fault recovery not confirmed')
    require(ssh(journal['victimTarget'], ['hostname'], allow_fail=True) is not None,
            'recovered host not reachable via SSH')
    if args.heal_mode == 'partition':
        nodes = multi.parse_nodes(args.node)
        require(args.victim in nodes and nodes[args.victim] == journal['victimTarget'],
                'partition recovery observer hosts do not match durable journal')
        require(all(peer_connectivity(args, nodes, args.victim).values()),
                'surviving hosts still cannot reach recovered application network')
    Path(args.state).unlink()
    return 0

def game_restore(args):
    # Выполняется на новом Linux-хосте восстановления игры после внешней аппаратной блокировки источника.
    # Безопасное восстановление мира использует ту же промышленную побайтовую проверку, что и DR.
    require(args.allow_disruption == 'I-ACCEPT-PHYSICAL-OUTAGE' and args.source_fenced,
            'world recovery requires explicit fencing and operator approval')
    # Старый сервер мира должен быть физически отключён, а не только объявлен отключённым аргументом CLI.
    # Считайте исходное состояние питания непосредственно через его BMC.
    require(bmc_status(args).get('PowerState') == 'Off',
            'original Minecraft world writer is not physically fenced')
    source, dest = Path(args.world_backup), Path(args.world_destination)
    require(source.is_absolute() and dest.is_absolute() and dest.parent.is_dir() and
            not dest.exists() and not dest.is_symlink(), 'world restore must use a fresh absolute directory')
    require(source != dest and source not in dest.parents and dest not in source.parents,
            'world recovery source and destination overlap')
    manifest = dr.safe_world_backup(source)
    dr.restore_world_backup(source, dest)
    dr.safe_world_restored(dest, manifest)
    # Этот этап запускается на реально восстановленном игровом хосте, а не сводится к сравнению хешей на
    # наблюдателе. Скрипты запуска и остановки JVM принадлежат оператору, имеют абсолютные пути и не являются
    # символическими ссылками. Массивы команд не вызывают shell.
    for name in ('game_start', 'game_stop'):
        path = Path(getattr(args, name))
        require(path.is_absolute() and path.is_file() and not path.is_symlink() and
                path.stat().st_mode & 0o111, 'missing executable real JVM control: ' + name)
    config = read_json(args.game_config)
    require(type(config) is dict and config.get('minecraftVersion') == '1.21.1' and
            type(config.get('minecraftPort')) is int and 1 <= config['minecraftPort'] <= 65535 and
            type(config.get('rconPort')) is int and 1 <= config['rconPort'] <= 65535 and
            Path(config.get('serverDir', '')).resolve() == dest.resolve(),
            'real Vanilla 1.21.1 game server must use actually restored world directory')
    password = private_bytes(Path(args.rcon_password_file), 4096).decode('utf-8').strip()
    require(re.fullmatch(r'[A-Za-z0-9_]{3,16}', args.expected_player or ''),
            'actual Minecraft player name required')
    started = False
    stopped = False
    result = {'schema': SCHEMA, 'version': VERSION, 'mode': 'world', 'status': 'BLOCKED',
              'worldBackupId': source.name, 'filesRestored': len(manifest['entries']),
              'worldManifestSha256': hashlib.sha256((source/'manifest.json').read_bytes()).hexdigest()}
    try:
        invoke([args.game_start], timeout=90)
        started = True
        until = time.monotonic() + args.timeout
        verified = False
        while time.monotonic() < until:
            try:
                vanilla.status('127.0.0.1', config['minecraftPort'], config['minecraftVersion'])
                players = vanilla.rcon('127.0.0.1', config['rconPort'], password, 'list')
                require(re.search(r'(?<![A-Za-z0-9_])' + re.escape(args.expected_player) +
                                  r'(?![A-Za-z0-9_])', players, flags=re.IGNORECASE),
                        'independent player has not joined restored game world')
                before = vanilla.rcon('127.0.0.1', config['rconPort'], password, 'time query gametime')
                time.sleep(2)
                after = vanilla.rcon('127.0.0.1', config['rconPort'], password, 'time query gametime')
                require(before != after, 'recovered world is not ticking')
                # Точный внутриигровой маркер состояния должен уже находиться в резервной копии исходного мира; его
                # содержимое задаёт оператор.
                require(re.fullmatch(r'-?[0-9]{1,7} -?[0-9]{1,7} -?[0-9]{1,7}', args.marker_xyz or ''),
                        'world marker coordinates required')
                require(re.fullmatch(r'minecraft:[a-z0-9_]{1,60}', args.marker_block or ''),
                        'world marker block required')
                marker = 'NLDR' + hashlib.sha256((source.name + args.expected_player).encode()).hexdigest()[:20]
                cmd = 'execute if block ' + args.marker_xyz + ' ' + args.marker_block + ' run say ' + marker
                response = vanilla.rcon('127.0.0.1', config['rconPort'], password, cmd)
                require(re.fullmatch(r'\[Server\]\s+' + re.escape(marker), response.strip()),
                        'restored world block state differs from snapshot')
                verified = True
                result['playerOnline'] = args.expected_player
                result['markerVerified'] = True
                break
            except (Blocked, vanilla.Blocked, OSError, ValueError, KeyError):
                time.sleep(2)
        require(verified, 'real player join/world state not observed')
    finally:
        if started:
            stopped = invoke([args.game_stop], timeout=90, allow_fail=True) is not None
    result['gameStopped'] = stopped
    result['status'] = 'PASS' if stopped and result.get('markerVerified') else 'BLOCKED'
    return output(args, result)

def dependency_drill(args):
    """Выполнить настоящий отказ HAProxy/Patroni/Redis/S3 и повторно его проверить."""
    require(args.allow_disruption == 'I-ACCEPT-PHYSICAL-OUTAGE',
            'live dependency failover needs explicit disruption approval')
    require(args.service in ('patroni', 'redis-server', 'minio') and args.backend_server and
            args.target and Path(args.ha_env_file).is_absolute(),
            'service, mapped backend SSH target and HA environment required')
    require(25 <= args.timeout <= 300, 'invalid failover deadline')
    cfg = dependency.validate(dependency.load_env(Path(args.ha_env_file)))
    creds = dependency.storage_credentials(dependency.load_env(Path(args.ha_env_file)))
    nodes = multi.parse_nodes(args.node) if args.node else {}
    before = dependency.perform_verification(Path(args.ha_socket), args.edge_url, nodes,
                                             redundant=True, cfg=cfg, creds=creds)
    require(before['healthy'], 'dependency baseline not healthy')
    require(args.state and Path(args.state).is_absolute() and not Path(args.state).exists(),
            'durable recovery journal required for dependency disruption')
    # Временный таймер на хосте зависимости восстановит службу, даже если контроллер приёмки завершится через
    # SIGKILL или потеряет административную сеть. systemctl start идемпотентен; таймер намеренно не
    # отменяется.
    unit = 'nl-ha-recover-' + secrets.token_hex(8)
    start = datetime.now(timezone.utc)
    save(args.state, {'schema': SCHEMA, 'mode': 'dependency', 'phase': 'recovery-required',
                      'service': args.service, 'target': args.target, 'backend': args.backend_server,
                      'scheduledUnit': unit, 'startedAt': start.isoformat()})
    ssh(args.target, ['sudo', '-n', 'systemd-run', '--unit=' + unit,
                      '--on-active=' + str(args.timeout + 90) + 's',
                      '--collect', '/usr/bin/systemctl', 'start', args.service])
    # Рабочий исполнитель останавливает РЕАЛЬНУЮ службу зависимости, наблюдает смену доступного для записи
    # основного узла (или оставшегося S3) и восстанавливает её модуль systemd.
    result = dependency.drill(Path(args.ha_socket), args.edge_url, nodes, args.service,
                              args.backend_server, args.target, args.timeout, cfg, creds)
    after = dependency.perform_verification(Path(args.ha_socket), args.edge_url, nodes,
                                            redundant=True, cfg=cfg, creds=creds)
    require(result['testPassed'] is True and after['healthy'],
            'dependency failover or recovery did not complete')
    require(result['stopExecuted'] and result['restorationReadinessObserved'] and
            any(row.get('newLeaderObserved') is True for row in result['observations']),
            'actual dependency leader failover not proven')
    delivery = alert_delivery(args, start)
    require(not Path(args.report).exists(), 'existing dependency report cannot be overwritten')
    result_code = output(args, {'schema': SCHEMA, 'version': VERSION, 'mode': 'dependency',
                         'status': 'PASS', 'service': args.service,
                         'backend': args.backend_server, 'failover': result,
                         'restored': after, 'downstreamAlert': delivery,
                         'startedAt': start.isoformat(), 'endedAt': now(),
                         'selfHealSystemdUnit': unit})
    if result_code == 0:
        Path(args.state).unlink()
    return result_code

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('host', 'partition', 'dependency', 'heal', 'world'))
    p.add_argument('--node', action='append', default=[])
    p.add_argument('--victim', default='')
    p.add_argument('--project', default='launcher')
    p.add_argument('--directory', default='/opt/launcher/deploy/production')
    p.add_argument('--remote-script', default='/opt/launcher/scripts/operations/multi_host_0512.py')
    p.add_argument('--edge-url', default='')
    p.add_argument('--redfish-url', default='')
    p.add_argument('--bmc-token-file', default='')
    p.add_argument('--bmc-ca', default='')
    p.add_argument('--expected-serial', default='')
    p.add_argument('--router', default='')
    p.add_argument('--ha-env-file', default='')
    p.add_argument('--ha-socket', default='/run/haproxy/launcher-ha.sock')
    p.add_argument('--service', default='')
    p.add_argument('--backend-server', default='')
    p.add_argument('--target', default='')
    p.add_argument('--victim-ip', default='')
    p.add_argument('--victim-port', type=int, default=443)
    p.add_argument('--ttl', type=int, default=120)
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--alertmanager-url', default='')
    p.add_argument('--delivery-url', default='')
    p.add_argument('--delivery-token-file', default='')
    p.add_argument('--alert-name', default='')
    p.add_argument('--allow-disruption', default='')
    p.add_argument('--state', default='')
    p.add_argument('--report', default='')
    p.add_argument('--heal-mode', choices=('host', 'partition', 'dependency'), default='host')
    p.add_argument('--world-backup', default='')
    p.add_argument('--world-destination', default='')
    p.add_argument('--game-start', default='')
    p.add_argument('--game-stop', default='')
    p.add_argument('--game-config', default='')
    p.add_argument('--rcon-password-file', default='')
    p.add_argument('--expected-player', default='')
    p.add_argument('--marker-xyz', default='')
    p.add_argument('--marker-block', default='')
    p.add_argument('--source-fenced', action='store_true')
    args = p.parse_args(argv)
    try:
        require((bool(args.state) and Path(args.state).is_absolute()) if args.mode == 'heal'
                else (bool(args.report) and Path(args.report).is_absolute() and
                      (args.mode == 'world' or
                       (bool(args.state) and Path(args.state).is_absolute()))),
                'absolute state/report paths required')
        if args.mode == 'heal':
            return heal(args)
        if args.mode == 'world':
            return game_restore(args)
        multi.validate_edge_url(args.edge_url)
        if args.mode == 'dependency':
            return dependency_drill(args)
        return live_fault(args)
    except (Blocked, multi.DeploymentError, chaos.ChaosError, dr.DrillError,
            vanilla.Blocked, OSError, ValueError, KeyError, TypeError) as exc:
        # В ошибках не должно быть учётных данных BMC, секретов RCON и вывода подпроцессов.
        print(json.dumps({'status': 'BLOCKED', 'mode': args.mode,
                          'reason': type(exc).__name__}), file=sys.stderr)
        return 3

if __name__ == '__main__':
    raise SystemExit(main())

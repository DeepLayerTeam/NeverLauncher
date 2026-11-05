#!/usr/bin/env python3
"""0.52.3: разрушающая приёмка одноразового владельца Standard и реального RemoteControl.

Необходимы выделенный Docker-хост Linux, ПРОВЕРЕННАЯ цепочка сертификатов HTTPS, настоящий
PostgreSQL и зарегистрированный закреплённый Minecraft-хост RemoteControl. Запускается промышленный
установщик продукта, а не подставной HTTP Backend. Ошибка, отсутствие MFA, ненаблюдавшаяся команда
или пропущенный маркер пользовательских данных блокируют запуск. Тестировщик владеет изолированным
пространством имён Compose, но не удаляет тома.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import base64
import hmac
import struct
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'install'))
import importlib.util

SPEC = importlib.util.spec_from_file_location('production_deploy_0523', ROOT / 'scripts/install/production-deploy.py')
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)
VERSION = (ROOT / 'VERSION').read_text().strip()


class Blocked(RuntimeError):
    pass


def require(condition, why):
    if not condition:
        raise Blocked(why)


def private_bytes(path: Path, *, max_size=8192) -> bytes:
    require(path.is_absolute() and not path.is_symlink(), 'private file must be an absolute regular path')
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
            st.st_mode & 0o077 == 0 and 0 < st.st_size <= max_size,
            'unsafe private file permissions/owner/size')
    return path.read_bytes().strip()


def sha_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), 'missing persistent user-data marker')
    size = path.stat().st_size
    require(0 < size <= 16 * 1024 * 1024, 'invalid user-data marker size')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def save_report(path: Path, data):
    require(path.is_absolute() and not path.is_symlink(), 'report path must be absolute')
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.parent.is_symlink(), 'unsafe report parent')
    temp = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(data, out, indent=2, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class HTTPS:
    def __init__(self, origin):
        parts = urlsplit(origin)
        require(parts.scheme == 'https' and parts.hostname and not parts.username
                and not parts.password and parts.path in ('', '/') and not parts.query
                and not parts.fragment, 'Standard requires an HTTPS origin')
        self.origin = origin.rstrip('/')
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def request(self, method, route, *, data=None, token=None, bootstrap=None,
                idempotency=None, expected=(200,), timeout=30):
        require(route.startswith('/api/v1/') or route in ('/health', '/ready'), 'non-API route')
        require(not route.startswith('//') and '\\' not in route and '#' not in route,
                'unsafe API route')
        body = json.dumps(data, separators=(',', ':')).encode('utf-8') if data is not None else None
        headers = {'Accept': 'application/json'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if bootstrap:
            headers['X-Launcher-Bootstrap-Token'] = bootstrap
        if idempotency:
            headers['Idempotency-Key'] = idempotency
        req = Request(self.origin + route, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                code, raw = resp.status, resp.read(1024 * 1024 + 1)
        except HTTPError as exc:
            code, raw = exc.code, exc.read(1024 * 1024 + 1)
        except (URLError, OSError, TimeoutError) as exc:
            raise Blocked('HTTPS connection/certificate failed: ' + type(exc).__name__) from None
        require(len(raw) <= 1024 * 1024 and code in expected,
                f'{method} {route.split("?")[0]}: HTTP {code}, expected {expected}')
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Blocked('malformed Backend JSON response') from None
        require(type(parsed) is dict, 'non-object Backend JSON')
        return parsed


def check(report, title, action):
    started = time.monotonic()
    value = action()
    report['checks'].append({'id': title, 'status': 'passed', 'durationMs': int((time.monotonic()-started)*1000)})
    print('PASS', title, flush=True)
    return value


def login(api, email, password):
    login_data = api.request('POST', '/api/v1/admin/login', data={'email': email, 'password': password})
    token = login_data.get('token')
    require(isinstance(token, str) and len(token) >= 20 and
            login_data.get('user', {}).get('email') == email, 'admin login missing identity/session')
    return token


def verify_project(api, project, profile, channel, description, email, password):
    token = login(api, email, password)
    doc = api.request('GET', '/api/v1/projects/' + project)
    require(doc.get('id') == project and doc.get('description') == description,
            'project identity/description was lost')
    profiles = api.request('GET', '/api/v1/projects/' + project + '/profiles')
    channels = api.request('GET', '/api/v1/projects/' + project + '/channels')
    require(any(row.get('id') == profile for row in profiles.get('items', [])), 'profile lost')
    require(any(row.get('id') == channel for row in channels.get('items', [])), 'channel lost')
    api.request('GET', '/api/v1/admin/audit', token=token)
    api.request('GET', '/api/v1/admin/audit', expected=(401, 403))
    return token


def create_project(api, email, password):
    token = login(api, email, password)
    api.request('POST', '/api/v1/admin/projects', data={'id': 'unauthorized-0523'}, expected=(401, 403))
    project = 'real-owner-0523-' + secrets.token_hex(6)
    profile, channel = 'owner-vanilla', 'owner-acceptance'
    description = 'Persisted real owner workflow 0523 ' + secrets.token_hex(8)
    base = '/api/v1/admin/projects/' + project
    created = api.request('POST', '/api/v1/admin/projects', token=token,
                          data={'id': project, 'name': 'Real E2E Owner 0523', 'defaultChannel': 'stable'}, expected=(201,))
    require(created.get('data', {}).get('project', {}).get('id') == project, 'project create response invalid')
    api.request('PATCH', base, token=token, data={'description': description})
    made_profile = api.request('POST', base + '/profiles', token=token, expected=(201,),
                               data={'id': profile, 'name': 'Vanilla owner test', 'loader': 'vanilla'})
    require(made_profile.get('data', {}).get('profile', {}).get('id') == profile, 'profile creation invalid')
    made_channel = api.request('POST', base + '/channels', token=token, expected=(201,),
                               data={'id': channel, 'name': 'Real acceptance', 'protected': True})
    require(made_channel.get('data', {}).get('channel', {}).get('id') == channel, 'channel creation invalid')
    verify_project(api, project, profile, channel, description, email, password)
    # Черновик недоступен для чтения как опубликованный стабильный выпуск.
    api.request('GET', '/api/v1/projects/' + project + '/profiles/' + profile + '/manifest?channel=' + channel,
                expected=(404,))
    return project, profile, channel, description


def host_status(api, server_id, token):
    doc = api.request('GET', f'/api/v1/server-bridge/servers/{quote(server_id)}/host/status', token=token)
    content = doc.get('data', {})
    require(isinstance(content.get('host', {}).get('status', {}).get('processAlive'), bool)
            and content.get('bridge', {}).get('serverId') == server_id,
            'not a provisioned live JVM host')
    return content


def host_action(api, server_id, token, action):
    route = f'/api/v1/server-bridge/servers/{quote(server_id)}/host/operations'
    key = 'owner0523-' + secrets.token_hex(16)
    doc = api.request('POST', route, token=token, idempotency=key,
                      data={'action': action}, expected=(201, 202), timeout=125)
    data = doc.get('data', {})
    op = data.get('operation', {})
    require(op.get('action') == action and op.get('id') and not data.get('idempotentReplay'),
            'missing real durable host-operation intent')
    operation_id = op['id']
    replay = api.request('POST', route, token=token, idempotency=key,
                         data={'action': action}, expected=(200,), timeout=30)
    require(replay.get('data', {}).get('idempotentReplay') is True and
            replay['data'].get('operation', {}).get('id') == operation_id,
            'host operation idempotency not enforced')
    until = time.monotonic() + 120
    while time.monotonic() < until:
        refreshed = api.request('GET', route + '/' + quote(operation_id) + '?refresh=1', token=token)
        state = refreshed.get('data', {}).get('hostState')
        if state == 'succeeded':
            return refreshed
        require(state in ('accepted', 'indeterminate'), 'remote JVM action rejected or failed')
        time.sleep(2)
    raise Blocked('real remote JVM action was not verified succeeded: ' + action)


def totp_now(secret, at=None):
    """TOTP по RFC 6238 используется только для регистрации временного тестового владельца 0.52.3."""
    when = int(time.time() if at is None else at) // 30
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack('>Q', when), hashlib.sha1).digest()
    offset = mac[-1] & 15
    number = struct.unpack('>I', mac[offset:offset+4])[0] & 0x7fffffff
    return f'{number % 1000000:06d}'


def establish_real_mfa(api, email, password):
    """Зарегистрировать настоящий секрет TOTP, затем получить новый JWT после повторной проверки подлинности."""
    access = login(api, email, password)
    response = api.request('POST', '/api/v1/auth/totp/enroll', token=access, data={})
    secret = response.get('data', {}).get('secret')
    require(isinstance(secret, str) and len(secret) >= 16, 'TOTP enrollment secret missing')
    code = totp_now(secret)
    verified = api.request('POST', '/api/v1/auth/totp/verify', token=access,
                           data={'code': code})
    require(verified.get('data', {}).get('status') == 'totp-enabled',
            'TOTP verification did not enable MFA')
    # Проверка может потребить временной шаг; предоставьте следующий уникальный шаг, если проверка и
    # дополнительное подтверждение попадают в одно окно (политика Backend).
    stepped = api.request('POST', '/api/v1/auth/mfa/step-up/totp', token=access,
                          data={'totp': totp_now(secret)})
    result = stepped.get('data', {})
    token = result.get('accessToken')
    require(result.get('status') == 'stepped-up' and isinstance(token, str) and len(token) > 20,
            'real MFA step-up did not issue fresh admin session')
    return token


def real_game_command(api, server_id, token):
    """Отправить разрешённую консольную команду и дождаться реального ACK игрового агента."""
    route = f'/api/v1/server-bridge/servers/{quote(server_id)}/control'
    request = {'type': 'server.console', 'payload': {'command': 'list'},
               'idempotencyKey': 'owner0523-console-' + secrets.token_hex(12),
               'expiresInSeconds': 120}
    result = api.request('POST', route, data=request, token=token, expected=(201,))
    command = result.get('data', {}).get('command', {})
    command_id = command.get('id')
    require(command.get('type') == 'server.console' and command_id and
            result.get('data', {}).get('idempotentReplay') is False,
            'real game console request was not persisted')
    until = time.monotonic() + 110
    while time.monotonic() < until:
        result = api.request('GET', route + '/' + quote(command_id), token=token)
        status = result.get('data', {}).get('command', {}).get('status')
        if status in ('executed', 'succeeded'):
            return
        require(status in ('pending', 'leased', 'accepted', 'delivered'),
                'game agent command failed, expired or was refused')
        time.sleep(2)
    raise Blocked('real Minecraft game agent did not acknowledge console command')


def run_host(api, server_id, token, marker):
    # Недоступный хост, принятая асинхронная команда или один ответ API не доказывают
    # настоящий запуск, остановку или перезапуск игрового процесса.
    initial = host_status(api, server_id, token)
    require(initial['host']['status']['processAlive'] is True and
            initial['host']['status']['supervisorAlive'] is True and
            initial['bridge']['status'] == 'active' and
            isinstance(initial['bridge']['runtimeId'], str) and initial['bridge']['runtimeId'] and
            isinstance(initial['bridge']['runtimeEpoch'], int) and initial['bridge']['runtimeEpoch'] >= 1,
            'dedicated Minecraft process/supervisor not running before test')
    marker_before = sha_file(marker)
    for action, expected_alive in (('stop', False), ('start', True), ('restart', True)):
        host_action(api, server_id, token, action)
        latest = host_status(api, server_id, token)
        require(latest['host']['status']['processAlive'] is expected_alive,
                'actual host process state does not match ' + action)
    require(sha_file(marker) == marker_before, 'Minecraft project/player data marker changed or disappeared')
    return marker_before


def deploy_call(env, action, *, email='', password_file=None):
    args = [sys.executable, str(ROOT / 'scripts/install/production-deploy.py'),
            'compose', action, '--mode', 'standard', '--env', str(env)]
    if action == 'first-admin':
        args += ['--email', email, '--display-name', '0523 Owner', '--password-file', str(password_file)]
    task = subprocess.run(args, capture_output=True, text=True, timeout=1800)
    require(task.returncode == 0, 'real production Compose ' + action + ' failed (inspect private runner logs)')


def no_existing_project(project):
    require(re.fullmatch(r'nl0523[a-z0-9]{8,20}', project) is not None,
            'Standard acceptance requires unique nl0523 Docker project namespace')
    require(shutil.which('docker'), 'Docker is required')
    for cmd in (['docker', 'ps', '-a', '--filter', 'label=com.docker.compose.project='+project, '--format', '{{.ID}}'],
                ['docker', 'volume', 'ls', '--filter', 'label=com.docker.compose.project='+project, '--quiet'],
                ['docker', 'network', 'ls', '--filter', 'label=com.docker.compose.project='+project, '--quiet']):
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        require(proc.returncode == 0 and not proc.stdout.strip(),
                'project namespace already used or Docker unavailable')


def execute(args, report):
    env = args.env.absolute()
    private_bytes(env, max_size=64*1024)
    values = DEPLOY.read_env(env)
    require(values.get('LAUNCHER_DEPLOYMENT_MODE') == 'standard' and
            values.get('LAUNCHER_REPOSITORY_DRIVER') == 'postgres' and
            values.get('LAUNCHER_IMAGE_TAG') == VERSION and
            all(values.get(name) for name in ('LAUNCHER_0523_HOST_TARGETS_FILE',
                 'LAUNCHER_0523_HOST_CA_FILE', 'LAUNCHER_0523_HOST_TOKEN_FILE')), 
            'incorrect Standard/PostgreSQL/current-version installation')
    require(not (env.parent / '.launcher-compose-state.json').exists(),
            'fresh Standard instance required, existing deployment cannot be overwritten')
    require(not os.environ.get('GITHUB_SHA') or
            values.get('LAUNCHER_SOURCE_COMMIT') == os.environ['GITHUB_SHA'],
            'Standard release image commit must match exact checkout')
    project_name = DEPLOY.compose_project(values)
    check(report, 'unused_isolated_compose_project', lambda: no_existing_project(project_name))
    password = private_bytes(args.password_file.absolute()).decode('utf-8')
    require(len(password) >= 12 and '\n' not in password and '\r' not in password,
            'invalid administrator password file')
    require(args.server_id and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{2,100}', args.server_id),
            'dedicated registered game server ID required')
    marker = args.world_marker.absolute()
    require(sha_file(marker), 'existing game data marker required')
    api = HTTPS(values['LAUNCHER_PUBLIC_URL'])
    report['mode'] = 'standard-postgresql-real-compose-https-remote-jvm'
    report['dockerProject'] = project_name
    report['serverId'] = args.server_id
    report['sourceCommit'] = os.environ.get('GITHUB_SHA', '')
    check(report, 'production_compose_preflight', lambda: deploy_call(env, 'check'))
    # Неудачный запуск сохраняет тома для расследования. База данных никогда не очищается.
    check(report, 'fresh_postgres_compose_install', lambda: deploy_call(env, 'up'))
    def first_ready():
        doc = api.request('GET', '/ready')
        require(doc.get('status') == 'ready' and doc.get('version') == VERSION and
                doc.get('repository') == 'postgres', 'wrong live Standard backend')
        checkout = os.environ.get('GITHUB_SHA', '')
        require(not checkout or doc.get('sourceCommit') == checkout,
                'deployed backend is not built from exact source commit')
        require(api.request('GET', '/api/v1/install/readiness').get('data', {}).get('bootstrapTokenConsumed') is False,
                'owner already exists; not a fresh installation')
    check(report, 'real_https_postgres_ready', first_ready)
    def first_admin():
        api.request('POST', '/api/v1/install/bootstrap-admin', data={'email': args.email, 'password': password},
                    expected=(403,))
        deploy_call(env, 'first-admin', email=args.email, password_file=args.password_file)
        api.request('POST', '/api/v1/install/bootstrap-admin', data={'email': args.email, 'password': password},
                    bootstrap=values['LAUNCHER_BOOTSTRAP_TOKEN'], expected=(403,))
        require(api.request('GET', '/api/v1/install/readiness').get('data', {}).get('bootstrapTokenConsumed') is True,
                'bootstrap token not consumed')
        login(api, args.email, password)
    check(report, 'one_time_real_owner_bootstrap', first_admin)
    def first_project():
        token = login(api, args.email, password)
        project = 'initial-0523-' + secrets.token_hex(6)
        created = api.request('POST', '/api/v1/install/first-project', token=token, expected=(201,),
                              data={'projectId': project, 'profileId': 'vanilla', 'channel': 'stable', 'version': '0.1.0'})
        require(created.get('data', {}).get('installationCompleted') is True,
                'first-project installation failed')
        require(api.request('GET', '/api/v1/projects/'+project).get('id') == project,
                'first project not persisted')
        return project
    initial_project = check(report, 'first_project_and_draft', first_project)
    state = check(report, 'owner_admin_crud_and_audit', lambda: create_project(api, args.email, password))
    def register_live_server():
        registration_bytes = private_bytes(args.bridge_registration_file.absolute(), max_size=8192)
        request = json.loads(registration_bytes)
        require(type(request) is dict and request.get('id') == args.server_id and
                request.get('projectId') in (None, '', state[0]) and
                request.get('profileId') in (None, '', state[2]) and
                request.get('publicKey') and request.get('keyAlgorithm'),
                'Bridge registration does not match current test project/real node key')
        request['projectId'], request['profileId'] = state[0], state[2]
        token = login(api, args.email, password)
        registered = api.request('POST', '/api/v1/server-bridge/servers/register', token=token,
                                 data=request, expected=(201,))
        require(registered.get('data', {}).get('server', {}).get('id') == args.server_id,
                'pinned ServerBridge public key registration failed')
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                observed = host_status(api, args.server_id, token)
                bridge = observed['bridge']
                if bridge.get('runtimeId') and bridge.get('runtimeEpoch', 0) >= 1:
                    return
            except (Blocked, KeyError):
                pass
            time.sleep(2)
        raise Blocked('real signed ServerBridge heartbeat was not observed after registration')
    check(report, 'pinned_serverbridge_registration_and_live_heartbeat', register_live_server)
    mfa_token = check(report, 'real_totp_enrollment_and_fresh_mfa_session',
                      lambda: establish_real_mfa(api, args.email, password))
    check(report, 'real_minecraft_console_command_ack',
          lambda: real_game_command(api, args.server_id, mfa_token))
    world_hash = check(report, 'dedicated_minecraft_stop_start_restart_and_data',
                       lambda: run_host(api, args.server_id, mfa_token, marker))
    check(report, 'standard_real_compose_shutdown', lambda: deploy_call(env, 'down'))
    check(report, 'standard_real_compose_restart', lambda: deploy_call(env, 'up'))
    def after_restart():
        ready = api.request('GET', '/ready')
        require(ready.get('status') == 'ready' and ready.get('repository') == 'postgres',
                'PostgreSQL not ready after restart')
        require(api.request('GET', '/api/v1/install/readiness').get('data', {}).get('installationCompleted') is True,
                'first installer state lost after restart')
        require(api.request('GET', '/api/v1/projects/' + initial_project).get('id') == initial_project,
                'first project lost after restart')
        verify_project(api, *state, args.email, password)
        require(sha_file(marker) == world_hash, 'game data changed or disappeared after Compose restart')
    check(report, 'owner_login_projects_profiles_channels_after_restart', after_restart)
    check(report, 'standard_compose_final_shutdown_retaining_data', lambda: deploy_call(env, 'down'))
    report['persistentProjectId'] = state[0]
    report['firstProjectId'] = initial_project
    report['storage'] = 'real PostgreSQL and existing dedicated Minecraft data marker'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--env', type=Path, required=True, help="Существующий закрытый производственный .env Standard; уникальный проект Compose")
    p.add_argument('--email', required=True)
    p.add_argument('--password-file', type=Path, required=True)
    p.add_argument('--server-id', required=True, help="Выделенный НАСТОЯЩИЙ узел Minecraft ServerBridge")
    p.add_argument('--bridge-registration-file', type=Path, required=True,
                   help="Закрытый JSON: ID/тип реального узла и открытый ключ Ed25519 (никогда не закрытый)")
    p.add_argument('--world-marker', type=Path, required=True, help="Существующий устойчивый файл пользовательских данных на выделенном хосте")
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--isolated-destructive-acceptance', action='store_true',
                   help="Подтвердить запуск, остановку и перезапуск настоящего выделенного Minecraft-хоста и проекта Docker")
    args = p.parse_args(argv)
    report = {'schemaVersion': 'neverlauncher.owner-admin-real-e2e.0.52.3',
              'productVersion': VERSION, 'status': 'blocked', 'startedAt': datetime.now(timezone.utc).isoformat(),
              'checks': [], 'gaCertified': False, 'nativeMinecraftMatrixCertified': False}
    code = 1
    try:
        require(args.isolated_destructive_acceptance, 'explicit destructive acceptance consent required')
        execute(args, report)
        require(len(report['checks']) >= 14, 'incomplete owner/admin acceptance')
        report['status'] = 'passed'
        code = 0
    except (Blocked, ValueError, UnicodeError, OSError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        # НИКОГДА не включайте серверные ответы, секреты и значения окружения в опубликованные артефакты.
        report['failureType'] = type(exc).__name__
        report['failure'] = 'real installation/owner/host operation failed; consult private runner logs'
        print('BLOCKED owner/admin E2E: ' + type(exc).__name__, file=sys.stderr)
    finally:
        report['finishedAt'] = datetime.now(timezone.utc).isoformat()
        save_report(args.report.absolute(), report)
    return code


if __name__ == '__main__':
    sys.exit(main())

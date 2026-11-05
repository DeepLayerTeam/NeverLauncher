#!/usr/bin/env python3
"""Провести независимую приёмку NeverLauncher на реальных Linux-службах.

Четыре взаимоисключающих эксплуатационных этапа. Каждый вызывает производственные команды
установки/обновления/восстановления/хаос-тестов (не имитацию готовности и не декларативный план),
проверяет результаты и публикует закрытую неизменяемую квитанцию успеха. При ошибке PASS никогда не
выдаётся; восстановление/fencing выполняет базовая эксплуатационная утилита. Сетевое переключение
ограничено лабораториями nl-dr. Оператор должен организовать настоящие независимые машины, пароли и
снимки.
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
import subprocess
import sys
import ssl
import urllib.request
import urllib.error
import tempfile

import operator_accept_04513 as live
import dr_03512 as dr

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / 'scripts/install/production-deploy.py'
UPGRADE = ROOT / 'scripts/operations/component_upgrade_0458.py'
DR = ROOT / 'scripts/operations/dr_03512.py'
CHAOS = ROOT / 'scripts/operations/chaos_0456.py'
LIVE = ROOT / 'scripts/operations/operator_accept_04513.py'
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
VERSION_RE = re.compile(r'^0\.\d+\.\d+$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,63}$')
MAX_OUTPUT = 256 * 1024


class Rejected(RuntimeError):
    pass


def ensure(test, reason):
    if not test:
        raise Rejected(reason)


def sha(path: Path) -> str:
    with path.open('rb') as f:
        h = hashlib.sha256()
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
        return h.hexdigest()


def actor(primary: str) -> str:
    # Идентичность входа берётся из сессии ядра или источника sudo, а НЕ из
    # утверждения имени независимого оператора в командной строке.
    real_user = pwd.getpwuid(os.getuid()).pw_name
    sudo_user = os.environ.get('SUDO_USER', '') if os.geteuid() == 0 else ''
    if os.geteuid() == 0:
        ensure(bool(sudo_user) and sudo_user != 'root',
               'independent root operations require sudo from a named non-root operator')
    name = sudo_user or real_user
    ensure(USER_RE.fullmatch(name) and USER_RE.fullmatch(primary), 'invalid local operator identity')
    ensure(name != primary, 'primary operator cannot certify their own deployment')
    return name


def host_id() -> str:
    path = Path('/etc/machine-id')
    ensure(path.is_file() and not path.is_symlink(), 'Linux machine-id unavailable')
    raw = path.read_text(encoding='ascii').strip()
    ensure(re.fullmatch(r'[0-9a-f]{32}', raw) is not None, 'invalid Linux machine-id')
    return hashlib.sha256(('neverlauncher-operator-host:' + raw).encode()).hexdigest()


def require_version(value):
    ensure(VERSION_RE.fullmatch(value) is not None, 'invalid release version')


def private_file(path: Path) -> Path:
    ensure(path.is_absolute() and path.is_file() and not path.is_symlink()
           and not (path.stat().st_mode & 0o077), 'required private file missing or not mode 0600')
    return path


def report_target(path: Path):
    ensure(path.is_absolute() and not path.exists() and not path.is_symlink(), 'receipt path must be new absolute path')
    ensure(path.parent.is_dir() and not path.parent.is_symlink()
           and not (path.parent.stat().st_mode & 0o077), 'receipt directory must be private (0700)')


def invoke(argv: list[str], *, timeout: int = 2400, json_result: bool = False):
    """Запускать существующую разрешённую точку входа; не выводить stdout/stderr (секреты)."""
    ensure(argv[0] == sys.executable and Path(argv[1]).resolve() in (INSTALL, UPGRADE, DR, CHAOS, LIVE),
           'unsupported operational entrypoint')
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE if json_result else subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Rejected('operator command unavailable or timed out: ' + Path(argv[1]).name) from exc
    ensure(p.returncode == 0, 'operation failed: ' + Path(argv[1]).name)
    if not json_result:
        return None
    ensure(len(p.stdout) <= MAX_OUTPUT, 'operation returned excessive output')
    try:
        data = json.loads(p.stdout)
    except (UnicodeError, ValueError) as exc:
        raise Rejected('operational tool returned invalid JSON') from exc
    ensure(isinstance(data, dict), 'operational tool returned unexpected output')
    return data


def probe(mode, project, env, url, version):
    with tempfile.TemporaryDirectory(prefix='nl-04514-live-') as tmp:
        path = Path(tmp) / 'live.json'
        argv = [sys.executable, str(LIVE), 'live', '--mode', mode, '--project', project,
                '--env-file', str(env), '--url', url, '--version', version, '--report', str(path)]
        result = invoke(argv, timeout=120, json_result=True)
        ensure(result.get('status') == 'passed' and result.get('mode') == mode
               and result.get('scope') == 'read-only-live-readiness', 'actual backend readiness not verified')
        ensure(path.is_file() and path.stat().st_mode & 0o077 == 0, 'private live receipt missing')
        ensure(result == json.loads(path.read_text()), 'live receipt differs from command result')
        return {'sha256': sha(path), 'checks': sorted(result['checks']),
                'version': result['public']['version']}


def base_receipt(args, stage, started, operator):
    return {'schema': 1, 'status': 'passed', 'stage': stage, 'release': VERSION,
            'startedUtc': started, 'completedUtc': datetime.now(timezone.utc).isoformat(),
            'secondOperator': operator, 'firstOperator': args.primary_operator,
            'machineFingerprint': host_id(), 'scope': 'live execution of existing operational commands; no inferred cross-host certification'}


def read_receipt(path, stage):
    private_file(path)
    ensure(path.stat().st_size <= MAX_OUTPUT, 'receipt exceeds safety limit')
    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise Rejected('invalid source receipt') from exc
    ensure(isinstance(doc, dict) and doc.get('schema') == 1 and doc.get('status') == 'passed'
           and doc.get('stage') == stage, 'wrong or unverified receipt stage')
    return doc


def checked_env(env, version, mode, url):
    private_file(env)
    live.operator_env(env, expected_mode=mode, expected_version=version, public_url=url)


def assert_fresh_compose_project(project: str):
    # Потерянный файл состояния установщика не превращает ранее использованный
    # том PostgreSQL в чистую установку. Не принимайте чужие данные Compose.
    for kind, scope in (('ps', 'container'), ('volume', 'volume')):
        args = (['docker', 'ps', '-a'] if kind == 'ps' else ['docker', 'volume', 'ls'])
        args += ['--filter', 'label=com.docker.compose.project=' + project,
                 '--format', '{{.ID}}' if kind == 'ps' else '{{.Name}}']
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  check=False, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Rejected('Docker inventory cannot be checked') from exc
        ensure(proc.returncode == 0 and len(proc.stdout) < 128 * 1024,
               'Docker inventory failed closed')
        ensure(not proc.stdout.strip(), 'clean install blocked: existing Compose ' + scope)


def verify_old_owner(url: str, email: str, password_file: Path, project_id: str,
                     expected_version: str, totp_file: Path | None = None) -> dict:
    """Настоящий доверенный HTTPS-вход и авторизованное чтение существующего проекта.

    Токены, пароли и тела HTTP-ответов не записываются в свидетельства. Продолжение passkey
    намеренно BLOCKED и не выдаётся за аутентифицированный сеанс. TOTP однократно читается из файла
    с правами 0600.
    """
    live.checked_origin(url.removesuffix('/ready'))
    ensure('@' in email and 0 < len(email) <= 254 and not any(c.isspace() for c in email),
           'invalid existing administrator email')
    ensure(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,80}', project_id) is not None,
           'invalid project ID for recovered-data verification')
    private_file(password_file)
    ensure(password_file.stat().st_size <= 4096, 'administrator password file too large')
    password = password_file.read_text(encoding='utf-8').rstrip('\r\n')
    ensure(len(password) >= 12 and not any(c in password for c in '\x00\r\n'),
           'invalid administrator password file')
    body = {'email': email, 'password': password}
    if totp_file is not None:
        private_file(totp_file)
        totp = totp_file.read_text(encoding='ascii').strip()
        ensure(re.fullmatch(r'\d{6,8}', totp) is not None, 'invalid TOTP code')
        body['totp'] = totp
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    origin = url.removesuffix('/ready').rstrip('/')
    def request(path, payload=None, token=None):
        content = json.dumps(payload).encode() if payload is not None else None
        headers = {'Accept': 'application/json'}
        if content is not None: headers['Content-Type'] = 'application/json'
        if token is not None: headers['Authorization'] = 'Bearer ' + token
        q = urllib.request.Request(origin + path, data=content, headers=headers,
                                   method='POST' if content is not None else 'GET')
        try:
            with opener.open(q, timeout=15) as response:
                ensure(response.status == 200 and response.headers.get('Content-Type','').split(';')[0] == 'application/json',
                       'administrator HTTP verification failed')
                raw = response.read(1024 * 1024 + 1)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise Rejected('administrator login/authorization failed over trusted HTTPS') from exc
        ensure(len(raw) <= 1024 * 1024, 'administrator response too large')
        try: result = json.loads(raw)
        except (UnicodeError, ValueError) as exc: raise Rejected('administrator response invalid') from exc
        ensure(isinstance(result, dict), 'administrator response is not an object')
        return result
    session = request('/api/v1/admin/login', body)
    token = session.get('token')
    ensure(isinstance(token, str) and 24 <= len(token) <= 8192
           and isinstance(session.get('user'), dict) and session['user'].get('email') == email,
           'previous administrator account did not authenticate')
    me = request('/api/v1/admin/me', token=token)
    ensure(me.get('email') == email, 'restored session does not belong to original administrator')
    overview = request('/api/v1/admin/overview', token=token)
    ensure(overview.get('version') == expected_version and
           isinstance(overview.get('projects'), list) and
           any(isinstance(item, dict) and item.get('id') == project_id for item in overview['projects']),
           'expected pre-existing project is missing or inaccessible')
    return {'oldAdminLogin': 'verified', 'oldProjectId': project_id,
            'oldProjectRead': 'verified', 'backendVersion': expected_version}


def accept_install(args):
    ensure(args.project == 'launcher', 'production installer has fixed launcher Compose project')
    checked_env(args.env_file, args.version, 'standard', args.url)
    private_file(args.password_file)
    ensure(args.version == VERSION, 'install version must equal checked source release')
    ensure(not (args.env_file.parent / '.launcher-compose-state.json').exists(),
           'clean install required: existing deployment state found')
    assert_fresh_compose_project(args.project)
    for action in ('check', 'up'):
        invoke([sys.executable, str(INSTALL), 'compose', action, '--mode', 'standard', '--env', str(args.env_file)], timeout=2400)
    invoke([sys.executable, str(INSTALL), 'compose', 'first-admin', '--mode', 'standard',
            '--env', str(args.env_file), '--email', args.email, '--display-name', args.display_name,
            '--password-file', str(args.password_file)], timeout=180)
    check = probe('standard', args.project, args.env_file, args.url, args.version)
    return {'mode': 'standard', 'installedVersion': args.version, 'ready': check,
            'firstAdminCreatedAndLoginVerified': True,
            'limits': ['actual MFA enrolment and project creation require separate user evidence']}


def accept_upgrade(args):
    ensure(args.project == args.confirm and args.maintenance_approved,
           'must confirm exact source project and explicitly approve maintenance')
    require_version(args.from_version); require_version(args.to_version)
    checked_env(args.source_env, args.from_version, 'standard', args.url)
    checked_env(args.target_env, args.to_version, 'standard', args.url)
    ensure(args.from_version != args.to_version, 'source and target versions must differ')
    # Промышленный обновлятор компонентов собирает настоящие образы, создаёт
    # контрольную точку PostgreSQL/бинарных объектов и выполняет проверенный откат
    # прежних образов при ошибке.
    output = invoke([sys.executable, str(UPGRADE), 'standard', '--project', args.project,
                     '--confirm', args.confirm, '--source-env', str(args.source_env),
                     '--target-env', str(args.target_env), '--backup', str(args.snapshot),
                     '--from-version', args.from_version, '--to-version', args.to_version,
                     '--production-source', '--maintenance-approved'], timeout=3600, json_result=True)
    ensure(output.get('status') == 'upgraded' and output.get('from') == args.from_version
           and output.get('to') == args.to_version and output.get('backendVerified') is True,
           'component updater has not proved successful cutover')
    ensure((args.snapshot / 'manifest.json').is_file(), 'actual verified backup manifest missing')
    verify = invoke([sys.executable, str(DR), 'verify', '--snapshot', str(args.snapshot)],
                    timeout=300, json_result=True)
    ensure(verify.get('status') == 'verified' and verify.get('postgresArchiveChecked') is True,
           'independent backup verification failed')
    check = probe('standard', args.project, args.target_env, args.url, args.to_version)
    identity = verify_old_owner(args.url, args.admin_email, args.admin_password_file,
                                args.project_id, args.to_version, args.totp_file)
    return {'identity': identity, 'mode': 'standard', 'from': args.from_version, 'to': args.to_version,
            'backupManifestSha256': sha(args.snapshot / 'manifest.json'),
            'backupVerified': True, 'ready': check,
            'limits': ['component-only upgrade: PostgreSQL schema migration is a separate approved operation']}


def accept_restore(args):
    ensure(args.project == args.confirm and args.maintenance_approved,
           'must confirm exact restoration project and explicitly approve destructive restore')
    source = read_receipt(args.source_receipt, 'upgrade-standard')
    ensure(source.get('machineFingerprint') != host_id(),
           'restore must be run on a different Linux host from source upgrade')
    ensure(source.get('secondOperator') == args.primary_operator or
           source.get('firstOperator') == args.primary_operator,
           'first operator identity does not match supplied source receipt')
    snapshot_manifest = args.snapshot / 'manifest.json'
    ensure(snapshot_manifest.is_file() and sha(snapshot_manifest) == source.get('backupManifestSha256'),
           'snapshot does not match source upgrade backup')
    checked_env(args.env_file, source['from'], 'standard', args.url)
    restored = invoke([sys.executable, str(DR), 'restore-fresh', '--project', args.project,
                       '--confirm', args.confirm, '--env-file', str(args.env_file),
                       '--snapshot', str(args.snapshot), '--ready-url', args.url + '/ready' if not args.url.endswith('/ready') else args.url,
                       '--production-target', '--maintenance-approved'], timeout=3600, json_result=True)
    ensure(restored.get('applicationVerified') is True,
           'fresh host restore did not verify backend')
    try:
        check = probe('standard', args.project, args.env_file, args.url, source['from'])
        identity = verify_old_owner(args.url, args.admin_email, args.admin_password_file,
                                    args.project_id, source['from'], args.totp_file)
        ensure(args.project_id == source['identity']['oldProjectId'],
               'restored project does not match upgrade source')
    except Exception:
        # Даже корректно восстановленный PostgreSQL при неудачном повторном чтении
        # владельца и проекта НЕЛЬЗЯ открывать как принятую замену. Остановите
        # публичный вход И API, предотвращая новые записи до расследования
        # оператором.
        try:
            dr.compose(args.project, args.env_file, 'stop', '-t', '10',
                       'nginx', 'admin', 'api', timeout=45)
        except Exception as shutdown_exc:
            raise Rejected('restored data could not be accepted and target isolation failed') from shutdown_exc
        raise
    return {'identity': identity, 'mode': 'standard', 'recoveredVersion': source['from'],
            'sourceHostFingerprint': source['machineFingerprint'],
            'sourceReceiptSha256': sha(args.source_receipt),
            'backupManifestSha256': sha(snapshot_manifest), 'ready': check,
            'limits': ['readiness and restored database/volume bytes checked; prior admin login must be independently repeated']}


def accept_failover(args):
    ensure(args.project == args.confirm, 'must confirm exact isolated lab project')
    ensure(re.fullmatch(r'nl-dr-[a-z0-9][a-z0-9-]{0,35}', args.project) is not None,
           'destructive failover only allowed in isolated nl-dr-* projects')
    checked_env(args.env_file, args.version, 'network-ha', args.url)
    ensure(args.version == VERSION, 'failover test must use matching source release')
    # Скрипт хаос-тестов требует локальный вход/S3, проверяет настоящую
    # идентичность контейнера Docker, прерывает PostgreSQL/Redis/S3/API/сеть,
    # проверяет подтверждённые контрольные записи и восстанавливает службы в
    # finally.
    with tempfile.TemporaryDirectory(prefix='nl-04514-chaos-') as tmp:
        path = Path(tmp) / 'chaos.json'
        ran = invoke([sys.executable, str(CHAOS), '--project', args.project,
                      '--confirm', args.confirm, '--env-file', str(args.env_file),
                      '--ready-url', args.url, '--s3-endpoint', args.s3_endpoint,
                      '--s3-bucket', args.s3_bucket, '--report', str(path),
                      '--timeout', str(args.timeout)], timeout=1800, json_result=True)
        ensure(ran.get('status') == 'passed' and path.is_file(), 'chaos runner did not complete')
        detail = json.loads(path.read_text())
        faults = {event['fault'] for event in detail.get('events', [])}
        ensure(detail.get('status') == 'passed' and len(faults) == 5
               and {'postgres-stopped', 'redis-stopped', 's3-stopped', 'api-stopped',
                    'worker-a-network-partition'} == faults
               and detail.get('observedRpoSeconds') == 0,
               'actual dependency failover/canary checks were incomplete')
        return {'mode': 'isolated-network-ha', 'chaosSha256': sha(path),
                'faults': sorted(faults), 'rtoSecondsMaxMeasured': detail['rtoSecondsMax'],
                'rpoSecondsObservedCanaries': detail['observedRpoSeconds'],
                'limits': detail['limits']}


def accept_verify(args):
    records = {name: read_receipt(path, name) for name, path in (
        ('install-standard', args.install_receipt), ('upgrade-standard', args.upgrade_receipt),
        ('restore-standard', args.restore_receipt), ('failover-network-ha', args.failover_receipt))}
    inst, upgrade, restore, fail = (records[name] for name in records)
    # Свежая установка и обновление предыдущей версии могут выполняться на отдельных
    # исходных хостах.
    ensure(restore['machineFingerprint'] != upgrade['machineFingerprint'], 'restore reused original host')
    ensure(restore['sourceHostFingerprint'] == upgrade['machineFingerprint'], 'restore source mismatch')
    ensure(restore['sourceReceiptSha256'] == sha(args.upgrade_receipt), 'restore does not bind exact upgrade receipt')
    ensure(restore['backupManifestSha256'] == upgrade['backupManifestSha256'], 'restore and upgrade backups differ')
    ensure(inst['secondOperator'] == upgrade['secondOperator'] == restore['secondOperator'] == fail['secondOperator'],
           'second operator identity differs between stages')
    ensure(all(records[name]['release'] == VERSION for name in records), 'receipt release mismatch')
    ensure(inst['installedVersion'] == VERSION and upgrade['to'] == VERSION, 'install/upgrade target release differs')
    ensure(restore['recoveredVersion'] == upgrade['from'], 'restore did not use source-version checkpoint')
    ensure(all(records[name]['firstOperator'] == inst['firstOperator'] for name in records),
           'first-operator identity differs between stages')
    ensure(fail['faults'] == sorted(['postgres-stopped', 'redis-stopped', 's3-stopped', 'api-stopped',
                                    'worker-a-network-partition']), 'failover faults mismatch')
    return {'stages': {key: sha(path) for key, path in (
        ('install-standard', args.install_receipt), ('upgrade-standard', args.upgrade_receipt),
        ('restore-standard', args.restore_receipt), ('failover-network-ha', args.failover_receipt))},
        'result': 'four operational stage receipts internally consistent',
        'limits': ['receipts are not cryptographic signatures; operator and host credentials require external attestation',
                   'separate real-world MFA, Minecraft join, multi-host HA and RPO must still be certified']}


def atomic_report(path, value):
    report_target(path)
    fd, tmp_name = tempfile.mkstemp(prefix='.nl-04514-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f, indent=2, ensure_ascii=False)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.link(tmp_name, path)  # поведение O_EXCL: параллельный процесс не может перезаписать файл
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def parser_make():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='stage', required=True)
    def common(which):
        c = sub.add_parser(which)
        c.add_argument('--primary-operator', required=True, help="Имя учётной записи ОС основного оператора")
        c.add_argument('--report', type=Path, required=True)
        return c
    install = common('install-standard')
    install.add_argument('--env-file', type=Path, required=True)
    install.add_argument('--url', required=True)
    install.add_argument('--project', default='launcher')
    install.add_argument('--version', default=VERSION)
    install.add_argument('--email', required=True)
    install.add_argument('--display-name', default='Independent Operator')
    install.add_argument('--password-file', type=Path, required=True)
    upgrade = common('upgrade-standard')
    upgrade.add_argument('--project', required=True)
    upgrade.add_argument('--confirm', required=True)
    upgrade.add_argument('--source-env', type=Path, required=True)
    upgrade.add_argument('--target-env', type=Path, required=True)
    upgrade.add_argument('--from-version', required=True)
    upgrade.add_argument('--to-version', required=True)
    upgrade.add_argument('--snapshot', type=Path, required=True)
    upgrade.add_argument('--url', required=True)
    upgrade.add_argument('--admin-email', required=True)
    upgrade.add_argument('--admin-password-file', type=Path, required=True)
    upgrade.add_argument('--totp-file', type=Path)
    upgrade.add_argument('--project-id', required=True)
    upgrade.add_argument('--maintenance-approved', action='store_true')
    restore = common('restore-standard')
    restore.add_argument('--source-receipt', type=Path, required=True)
    restore.add_argument('--project', required=True)
    restore.add_argument('--confirm', required=True)
    restore.add_argument('--env-file', type=Path, required=True)
    restore.add_argument('--snapshot', type=Path, required=True)
    restore.add_argument('--url', required=True)
    restore.add_argument('--admin-email', required=True)
    restore.add_argument('--admin-password-file', type=Path, required=True)
    restore.add_argument('--totp-file', type=Path)
    restore.add_argument('--project-id', required=True)
    restore.add_argument('--maintenance-approved', action='store_true')
    failover = common('failover-network-ha')
    failover.add_argument('--project', required=True)
    failover.add_argument('--confirm', required=True)
    failover.add_argument('--env-file', type=Path, required=True)
    failover.add_argument('--url', required=True)
    failover.add_argument('--version', default=VERSION)
    failover.add_argument('--s3-endpoint', required=True)
    failover.add_argument('--s3-bucket', required=True)
    failover.add_argument('--timeout', type=int, default=120)
    aggregate = common('verify-receipts')
    for name in ('install', 'upgrade', 'restore', 'failover'):
        aggregate.add_argument('--' + name + '-receipt', type=Path, required=True)
    return p


def main(argv=None):
    args = parser_make().parse_args(argv)
    try:
        report_target(args.report)
        operator = actor(args.primary_operator)
        start = datetime.now(timezone.utc).isoformat()
        operations = {'install-standard': accept_install, 'upgrade-standard': accept_upgrade,
                      'restore-standard': accept_restore, 'failover-network-ha': accept_failover,
                      'verify-receipts': accept_verify}
        result = operations[args.stage](args)
        report = {**base_receipt(args, args.stage, start, operator), **result}
        atomic_report(args.report, report)
        print(json.dumps({'status': 'passed', 'stage': args.stage, 'receipt': str(args.report)}, ensure_ascii=False))
        return 0
    except (Rejected, live.AcceptanceError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        # Пути, argv, секреты, окружение и закрытые тела ответов backend никогда не выводятся.
        print(json.dumps({'status': 'failed', 'stage': args.stage,
                          'reason': str(exc) if isinstance(exc, Rejected) else 'operational verification failed'},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

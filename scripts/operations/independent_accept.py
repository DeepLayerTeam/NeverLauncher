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
               'Для независимых операций с правами root требуется sudo от указанного оператора, не являющегося root')
    name = sudo_user or real_user
    ensure(USER_RE.fullmatch(name) and USER_RE.fullmatch(primary), 'Недопустимый идентификатор локального оператора')
    ensure(name != primary, 'Основной оператор не может самостоятельно сертифицировать своё развёртывание')
    return name


def host_id() -> str:
    path = Path('/etc/machine-id')
    ensure(path.is_file() and not path.is_symlink(), 'Идентификатор machine-id Linux недоступен')
    raw = path.read_text(encoding='ascii').strip()
    ensure(re.fullmatch(r'[0-9a-f]{32}', raw) is not None, 'Недопустимый machine-id Linux')
    return hashlib.sha256(('neverlauncher-operator-host:' + raw).encode()).hexdigest()


def require_version(value):
    ensure(VERSION_RE.fullmatch(value) is not None, 'Недопустимая версия релиза')


def private_file(path: Path) -> Path:
    ensure(path.is_absolute() and path.is_file() and not path.is_symlink()
           and not (path.stat().st_mode & 0o077), 'Отсутствует обязательный закрытый файл или его права отличаются от 0600')
    return path


def report_target(path: Path):
    ensure(path.is_absolute() and not path.exists() and not path.is_symlink(), 'Путь квитанции должен быть новым абсолютным путём')
    ensure(path.parent.is_dir() and not path.parent.is_symlink()
           and not (path.parent.stat().st_mode & 0o077), 'Каталог квитанций должен иметь закрытые права доступа (0700)')


def invoke(argv: list[str], *, timeout: int = 2400, json_result: bool = False):
    """Запускать существующую разрешённую точку входа; не выводить stdout/stderr (секреты)."""
    ensure(argv[0] == sys.executable and Path(argv[1]).resolve() in (INSTALL, UPGRADE, DR, CHAOS, LIVE),
           'Неподдерживаемая точка входа эксплуатационной операции')
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE if json_result else subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Rejected('Команда оператора недоступна или превысила время ожидания: ' + Path(argv[1]).name) from exc
    ensure(p.returncode == 0, 'Операция завершилась ошибкой: ' + Path(argv[1]).name)
    if not json_result:
        return None
    ensure(len(p.stdout) <= MAX_OUTPUT, 'Операция вернула слишком большой объём данных')
    try:
        data = json.loads(p.stdout)
    except (UnicodeError, ValueError) as exc:
        raise Rejected('Эксплуатационная утилита вернула недопустимый JSON') from exc
    ensure(isinstance(data, dict), 'Эксплуатационная утилита вернула неожиданный результат')
    return data


def probe(mode, project, env, url, version):
    with tempfile.TemporaryDirectory(prefix='nl-04514-live-') as tmp:
        path = Path(tmp) / 'live.json'
        argv = [sys.executable, str(LIVE), 'live', '--mode', mode, '--project', project,
                '--env-file', str(env), '--url', url, '--version', version, '--report', str(path)]
        result = invoke(argv, timeout=120, json_result=True)
        ensure(result.get('status') == 'passed' and result.get('mode') == mode
               and result.get('scope') == 'read-only-live-readiness', 'Фактическая готовность Backend не подтверждена')
        ensure(path.is_file() and path.stat().st_mode & 0o077 == 0, 'Отсутствует закрытая квитанция о реальном выполнении')
        ensure(result == json.loads(path.read_text()), 'Подтверждение работающей системы отличается от результата команды')
        return {'sha256': sha(path), 'checks': sorted(result['checks']),
                'version': result['public']['version']}


def base_receipt(args, stage, started, operator):
    return {'schema': 1, 'status': 'passed', 'stage': stage, 'release': VERSION,
            'startedUtc': started, 'completedUtc': datetime.now(timezone.utc).isoformat(),
            'secondOperator': operator, 'firstOperator': args.primary_operator,
            'machineFingerprint': host_id(), 'scope': 'Реальное выполнение существующих эксплуатационных команд; межузловая сертификация автоматически не предполагается'}


def read_receipt(path, stage):
    private_file(path)
    ensure(path.stat().st_size <= MAX_OUTPUT, 'Размер квитанции превышает допустимое ограничение')
    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise Rejected('Недопустимая исходная квитанция') from exc
    ensure(isinstance(doc, dict) and doc.get('schema') == 1 and doc.get('status') == 'passed'
           and doc.get('stage') == stage, 'Неверный или непроверенный этап подтверждения')
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
            raise Rejected('Невозможно проверить инвентаризацию Docker') from exc
        ensure(proc.returncode == 0 and len(proc.stdout) < 128 * 1024,
               'Проверка инвентаризации Docker завершилась безопасным отказом')
        ensure(not proc.stdout.strip(), 'Чистая установка заблокирована: обнаружена существующая конфигурация Compose ' + scope)


def verify_old_owner(url: str, email: str, password_file: Path, project_id: str,
                     expected_version: str, totp_file: Path | None = None) -> dict:
    """Настоящий доверенный HTTPS-вход и авторизованное чтение существующего проекта.

    Токены, пароли и тела HTTP-ответов не записываются в свидетельства. Продолжение passkey
    намеренно BLOCKED и не выдаётся за аутентифицированный сеанс. TOTP однократно читается из файла
    с правами 0600.
    """
    live.checked_origin(url.removesuffix('/ready'))
    ensure('@' in email and 0 < len(email) <= 254 and not any(c.isspace() for c in email),
           'Недопустимый адрес электронной почты действующего администратора')
    ensure(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,80}', project_id) is not None,
           'Недопустимый ID проекта для проверки восстановленных данных')
    private_file(password_file)
    ensure(password_file.stat().st_size <= 4096, 'Файл пароля администратора слишком большой')
    password = password_file.read_text(encoding='utf-8').rstrip('\r\n')
    ensure(len(password) >= 12 and not any(c in password for c in '\x00\r\n'),
           'Недопустимый файл пароля администратора')
    body = {'email': email, 'password': password}
    if totp_file is not None:
        private_file(totp_file)
        totp = totp_file.read_text(encoding='ascii').strip()
        ensure(re.fullmatch(r'\d{6,8}', totp) is not None, 'Недопустимый код TOTP')
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
                       'HTTP-проверка администратора завершилась ошибкой')
                raw = response.read(1024 * 1024 + 1)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise Rejected('Вход или авторизация администратора через доверенный HTTPS завершились ошибкой') from exc
        ensure(len(raw) <= 1024 * 1024, 'Ответ администратора слишком большой')
        try: result = json.loads(raw)
        except (UnicodeError, ValueError) as exc: raise Rejected('Недопустимый ответ администратора') from exc
        ensure(isinstance(result, dict), 'Ответ администратора не является объектом')
        return result
    session = request('/api/v1/admin/login', body)
    token = session.get('token')
    ensure(isinstance(token, str) and 24 <= len(token) <= 8192
           and isinstance(session.get('user'), dict) and session['user'].get('email') == email,
           'Не удалось войти с прежней учётной записью администратора')
    me = request('/api/v1/admin/me', token=token)
    ensure(me.get('email') == email, 'Восстановленная сессия не принадлежит исходному администратору')
    overview = request('/api/v1/admin/overview', token=token)
    ensure(overview.get('version') == expected_version and
           isinstance(overview.get('projects'), list) and
           any(isinstance(item, dict) and item.get('id') == project_id for item in overview['projects']),
           'Ожидаемый существующий проект отсутствует или недоступен')
    return {'oldAdminLogin': 'verified', 'oldProjectId': project_id,
            'oldProjectRead': 'verified', 'backendVersion': expected_version}


def accept_install(args):
    ensure(args.project == 'launcher', 'Рабочий установщик использует фиксированный Compose-проект launcher')
    checked_env(args.env_file, args.version, 'standard', args.url)
    private_file(args.password_file)
    ensure(args.version == VERSION, 'Версия установки должна совпадать с проверенным исходным релизом')
    ensure(not (args.env_file.parent / '.launcher-compose-state.json').exists(),
           'Требуется чистая установка: найдено состояние существующего развёртывания')
    assert_fresh_compose_project(args.project)
    for action in ('check', 'up'):
        invoke([sys.executable, str(INSTALL), 'compose', action, '--mode', 'standard', '--env', str(args.env_file)], timeout=2400)
    invoke([sys.executable, str(INSTALL), 'compose', 'first-admin', '--mode', 'standard',
            '--env', str(args.env_file), '--email', args.email, '--display-name', args.display_name,
            '--password-file', str(args.password_file)], timeout=180)
    check = probe('standard', args.project, args.env_file, args.url, args.version)
    return {'mode': 'standard', 'installedVersion': args.version, 'ready': check,
            'firstAdminCreatedAndLoginVerified': True,
            'limits': ['Для фактической регистрации MFA и создания проекта необходимы отдельные доказательства действий пользователя']}


def accept_upgrade(args):
    ensure(args.project == args.confirm and args.maintenance_approved,
           'Необходимо подтвердить точный исходный проект и явно разрешить обслуживание')
    require_version(args.from_version); require_version(args.to_version)
    checked_env(args.source_env, args.from_version, 'standard', args.url)
    checked_env(args.target_env, args.to_version, 'standard', args.url)
    ensure(args.from_version != args.to_version, 'Исходная и целевая версии должны различаться')
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
           'Средство обновления компонентов не подтвердило успешное переключение')
    ensure((args.snapshot / 'manifest.json').is_file(), 'Отсутствует фактически проверенный манифест резервной копии')
    verify = invoke([sys.executable, str(DR), 'verify', '--snapshot', str(args.snapshot)],
                    timeout=300, json_result=True)
    ensure(verify.get('status') == 'verified' and verify.get('postgresArchiveChecked') is True,
           'Независимая проверка резервной копии завершилась ошибкой')
    check = probe('standard', args.project, args.target_env, args.url, args.to_version)
    identity = verify_old_owner(args.url, args.admin_email, args.admin_password_file,
                                args.project_id, args.to_version, args.totp_file)
    return {'identity': identity, 'mode': 'standard', 'from': args.from_version, 'to': args.to_version,
            'backupManifestSha256': sha(args.snapshot / 'manifest.json'),
            'backupVerified': True, 'ready': check,
            'limits': ['Обновление только компонентов: миграция схемы PostgreSQL выполняется отдельной утверждённой операцией']}


def accept_restore(args):
    ensure(args.project == args.confirm and args.maintenance_approved,
           'Необходимо подтвердить конкретный проект восстановления и явно разрешить восстановление с перезаписью данных')
    source = read_receipt(args.source_receipt, 'upgrade-standard')
    ensure(source.get('machineFingerprint') != host_id(),
           'Восстановление должно выполняться на другом Linux-узле, отличном от узла исходного обновления')
    ensure(source.get('secondOperator') == args.primary_operator or
           source.get('firstOperator') == args.primary_operator,
           'Идентификатор первого оператора не соответствует предоставленному исходному подтверждению')
    snapshot_manifest = args.snapshot / 'manifest.json'
    ensure(snapshot_manifest.is_file() and sha(snapshot_manifest) == source.get('backupManifestSha256'),
           'Снимок не соответствует исходной резервной копии обновления')
    checked_env(args.env_file, source['from'], 'standard', args.url)
    restored = invoke([sys.executable, str(DR), 'restore-fresh', '--project', args.project,
                       '--confirm', args.confirm, '--env-file', str(args.env_file),
                       '--snapshot', str(args.snapshot), '--ready-url', args.url + '/ready' if not args.url.endswith('/ready') else args.url,
                       '--production-target', '--maintenance-approved'], timeout=3600, json_result=True)
    ensure(restored.get('applicationVerified') is True,
           'При восстановлении на новом узле Backend не прошёл проверку')
    try:
        check = probe('standard', args.project, args.env_file, args.url, source['from'])
        identity = verify_old_owner(args.url, args.admin_email, args.admin_password_file,
                                    args.project_id, source['from'], args.totp_file)
        ensure(args.project_id == source['identity']['oldProjectId'],
               'Восстановленный проект не соответствует источнику обновления')
    except Exception:
        # Даже корректно восстановленный PostgreSQL при неудачном повторном чтении
        # владельца и проекта НЕЛЬЗЯ открывать как принятую замену. Остановите
        # публичный вход И API, предотвращая новые записи до расследования
        # оператором.
        try:
            dr.compose(args.project, args.env_file, 'stop', '-t', '10',
                       'nginx', 'admin', 'api', timeout=45)
        except Exception as shutdown_exc:
            raise Rejected('Восстановленные данные не удалось принять, а изоляция целевой среды не пройдена') from shutdown_exc
        raise
    return {'identity': identity, 'mode': 'standard', 'recoveredVersion': source['from'],
            'sourceHostFingerprint': source['machineFingerprint'],
            'sourceReceiptSha256': sha(args.source_receipt),
            'backupManifestSha256': sha(snapshot_manifest), 'ready': check,
            'limits': ['Готовность, восстановленные байты БД и томов проверены; предыдущий вход администратора нужно независимо повторить']}


def accept_failover(args):
    ensure(args.project == args.confirm, 'Необходимо подтвердить точный идентификатор изолированного тестового проекта')
    ensure(re.fullmatch(r'nl-dr-[a-z0-9][a-z0-9-]{0,35}', args.project) is not None,
           'Разрушающее переключение допускается только в изолированных проектах nl-dr-*')
    checked_env(args.env_file, args.version, 'network-ha', args.url)
    ensure(args.version == VERSION, 'Тест переключения при отказе должен использовать соответствующий исходный релиз')
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
        ensure(ran.get('status') == 'passed' and path.is_file(), 'Сценарий испытания отказов не завершился')
        detail = json.loads(path.read_text())
        faults = {event['fault'] for event in detail.get('events', [])}
        ensure(detail.get('status') == 'passed' and len(faults) == 5
               and {'postgres-stopped', 'redis-stopped', 's3-stopped', 'api-stopped',
                    'worker-a-network-partition'} == faults
               and detail.get('observedRpoSeconds') == 0,
               'Фактические проверки переключения зависимостей и контрольных запросов не завершены')
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
    ensure(restore['machineFingerprint'] != upgrade['machineFingerprint'], 'При восстановлении повторно использован исходный узел')
    ensure(restore['sourceHostFingerprint'] == upgrade['machineFingerprint'], 'Несовпадение источника восстановления')
    ensure(restore['sourceReceiptSha256'] == sha(args.upgrade_receipt), 'Восстановление не привязано к точному подтверждению обновления')
    ensure(restore['backupManifestSha256'] == upgrade['backupManifestSha256'], 'Резервные копии восстановления и обновления различаются')
    ensure(inst['secondOperator'] == upgrade['secondOperator'] == restore['secondOperator'] == fail['secondOperator'],
           'Идентификатор второго оператора различается между этапами')
    ensure(all(records[name]['release'] == VERSION for name in records), 'Несовпадение релиза в квитанции')
    ensure(inst['installedVersion'] == VERSION and upgrade['to'] == VERSION, 'install/upgrade target release differs')
    ensure(restore['recoveredVersion'] == upgrade['from'], 'При восстановлении не использована контрольная точка исходной версии')
    ensure(all(records[name]['firstOperator'] == inst['firstOperator'] for name in records),
           'Идентификатор первого оператора различается между этапами')
    ensure(fail['faults'] == sorted(['postgres-stopped', 'redis-stopped', 's3-stopped', 'api-stopped',
                                    'worker-a-network-partition']), 'Несовпадение неисправностей в тесте переключения')
    return {'stages': {key: sha(path) for key, path in (
        ('install-standard', args.install_receipt), ('upgrade-standard', args.upgrade_receipt),
        ('restore-standard', args.restore_receipt), ('failover-network-ha', args.failover_receipt))},
        'result': 'four operational stage receipts internally consistent',
        'limits': ['Квитанции не являются криптографическими подписями; данные оператора и узла требуют внешней аттестации',
                   'Отдельно необходимо подтвердить MFA, подключение к Minecraft, отказоустойчивость нескольких узлов и RPO в реальных условиях']}


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
                          'reason': str(exc) if isinstance(exc, Rejected) else 'Эксплуатационная проверка завершилась ошибкой'},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

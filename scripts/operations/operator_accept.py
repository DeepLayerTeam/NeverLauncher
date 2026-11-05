#!/usr/bin/env python3
"""Приёмка оператора только для чтения на живых системах NeverLauncher 0.45.13.

Работает с существующими процессами и проверяет настоящую готовность и владельца хранилища. Не
создаёт пользователей, не мигрирует схемы, не сбрасывает аренды и не публикует успех при частичной
ошибке. Весь вывод ограничен белым списком: окружение, HTTP-тела при сбое, данные Docker inspect и
исходный stderr команд не попадают в отчёты.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STANDARD = ROOT / 'deploy/production/docker-compose.yml'
HA = ROOT / 'deploy/production/docker-compose.network-ha.yml'
DOCS = ROOT / 'docs/operator'
VERSION = ROOT / 'VERSION'
CHECKS = {
    'minimal': ('api',),
    'standard': ('postgres', 'api', 'admin', 'nginx'),
    'network-ha': ('postgres', 'redis', 'api', 'api-b', 'worker-a', 'worker-b', 'admin', 'nginx'),
}
DOC_FILES = ('README.md', 'installation.md', 'backup-recovery.md', 'upgrades.md',
             'ha-incidents.md', 'security-delivery.md', 'operator-checklist.md')
MAX_HTTP = 64 * 1024


class AcceptanceError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AcceptanceError(message)


def run(args, *, timeout=30):
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError('Обязательная команда недоступна или превысила время ожидания: ' + args[0]) from exc
    require(proc.returncode == 0, 'Обязательная команда завершилась ошибкой: ' + args[0])
    require(len(proc.stdout) <= 512 * 1024, 'Вывод команды превышает допустимый безопасный размер')
    return proc.stdout


def inspect_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise AcceptanceError('Некорректный публичный URL проверки готовности') from exc
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and
            not parsed.password and parsed.path in ('', '/ready') and not parsed.query and
            not parsed.fragment and port in (None, 443),
            'Публичный URL проверки готовности должен использовать HTTPS без учётных данных и параметров запроса')
    return value.rstrip('/') if parsed.path == '/ready' else value.rstrip('/') + '/ready'


def ready(url, expected_version, repository, storage, *, opener=None):
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(inspect_url(url), headers={'Accept': 'application/json'})
    try:
        with opener(request, timeout=15) as response:
            require(response.status == 200, 'Проверка готовности по HTTPS не вернула HTTP 200')
            require(response.headers.get('Content-Type', '').split(';')[0].strip() == 'application/json',
                    'Ответ проверки готовности по HTTPS не является JSON')
            raw = response.read(MAX_HTTP + 1)
    except (OSError, ValueError) as exc:
        raise AcceptanceError('Публичная проверка готовности HTTPS не пройдена') from exc
    require(len(raw) <= MAX_HTTP, 'Ответ проверки готовности слишком большой')
    try:
        payload = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise AcceptanceError('Некорректный JSON состояния готовности') from exc
    require(isinstance(payload, dict), 'Некорректное тело ответа проверки готовности')
    require(payload.get('status') == 'ready', 'Backend не готов к работе')
    require(payload.get('version') == expected_version, 'Версия работающего Backend не совпадает с ожидаемой')
    require(payload.get('repository') == repository, 'Обнаружено неожиданное активное хранилище репозитория')
    require(payload.get('storage') == storage, 'Обнаружен неожиданный активный драйвер хранилища')
    return {'status': 'ready', 'version': expected_version,
            'repository': repository, 'storage': storage}


def compose_command(project, env, mode, *command):
    argv = ['docker', 'compose', '-p', project, '--env-file', str(env)]
    if mode == 'network-ha':
        argv.extend(['--profile', 'network-ha'])
    argv.extend(['-f', str(STANDARD)])
    if mode == 'network-ha':
        argv.extend(['-f', str(HA)])
    return argv + list(command)


def parse_ps(raw):
    try:
        txt = raw.decode('utf-8').strip()
        entries = (json.loads(txt) if txt.startswith('[') else
                   [json.loads(line) for line in txt.splitlines()]) if txt else []
    except (UnicodeError, ValueError) as exc:
        raise AcceptanceError('Некорректный ответ Docker Compose ps') from exc
    if isinstance(entries, dict):
        entries = [entries]
    require(isinstance(entries, list), 'Некорректный список служб Compose')
    services = {}
    for entry in entries:
        require(isinstance(entry, dict) and isinstance(entry.get('Service'), str),
                'Некорректная служба Compose')
        name = entry['Service']
        require(name not in services, 'Несколько контейнеров в службе ' + name)
        state = str(entry.get('State', '')).lower()
        health = str(entry.get('Health', '')).lower()
        services[name] = {'state': state, 'health': health}
    return services


def checked_origin(value):
    url = urllib.parse.urlsplit(value)
    try:
        port = url.port
    except ValueError as exc:
        raise AcceptanceError('Некорректный источник развёртывания') from exc
    require(url.scheme == 'https' and url.hostname and not url.username and
            not url.password and url.path in ('', '/') and not url.query and
            not url.fragment and port in (None, 443),
            'Адрес развёртывания должен использовать доверенный стандартный HTTPS')
    return value.rstrip('/')


def operator_env(path, *, expected_mode, expected_version, public_url, minimal=False):
    require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0,
            'Закрытый файл окружения развёртывания отсутствует или небезопасен')
    require(path.stat().st_size < 256 * 1024, 'Файл окружения развёртывания слишком большой')
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        require('=' in line, 'Некорректный формат окружения развёртывания')
        key, val = line.split('=', 1)
        key = key.strip()
        require(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', key) is not None and key not in values,
                'Некорректная или повторяющаяся запись окружения развёртывания')
        values[key] = val.strip().strip('\"').strip("'")
    origin = checked_origin(public_url.removesuffix('/ready'))
    require(values.get('LAUNCHER_PUBLIC_URL', '').rstrip('/') == origin,
            'Активный HTTPS-адрес не соответствует выбранному окружению развёртывания')
    mode = values.get('LAUNCHER_DEPLOYMENT_MODE', '')
    require(mode == ('single-node' if minimal else expected_mode),
            'Режим развёртывания не совпадает с ожидаемым')
    if not minimal:
        require(values.get('LAUNCHER_IMAGE_TAG') == expected_version,
                'Версия образа развёртывания отличается от ожидаемой')
    return values


def probe_compose(project, env, mode):
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,60}', project) is not None,
            'Некорректное имя проекта')
    require(env.is_file() and not env.is_symlink() and env.stat().st_mode & 0o077 == 0,
            'Файл окружения Compose должен существовать, быть закрытым (0600) и не быть символьной ссылкой')
    states = parse_ps(run(compose_command(project, env, mode, 'ps', '--all', '--format', 'json')))
    checked = {}
    for name in CHECKS[mode]:
        entry = states.get(name)
        require(entry is not None and entry['state'] == 'running', name + ' не запущен')
        require(entry['health'] == 'healthy' if name != 'nginx' else entry['health'] in ('', 'healthy'),
                name + ' не прошёл проверку работоспособности')
        checked[name] = entry['health'] or 'running (no healthcheck)'
    if mode == 'network-ha':
        # Проверяйте готовность настоящего backend и отдельного рабочего процесса
        # напрямую; один публичный Nginx не доказывает возобновление опроса PostgreSQL.
        for name in ('api', 'api-b', 'worker-a', 'worker-b'):
            output = run(compose_command(project, env, mode, 'exec', '-T', name,
                                         'wget', '-qO-', 'http://127.0.0.1:8080/ready'))
            try:
                internal = json.loads(output)
            except (UnicodeError, ValueError) as exc:
                raise AcceptanceError(name + ' вернул некорректный JSON состояния готовности') from exc
            require(internal.get('status') == 'ready' and internal.get('repository') == 'postgres',
                    name + ' не готов к работе с PostgreSQL')
            require(internal.get('storage') == 's3', name + ' не использует общее хранилище S3')
            checked[name] = 'Готово (внутренние зависимости проверены)'
    return checked


def probe_minimal(root):
    require(root.is_dir() and not root.is_symlink(), 'Корневой каталог минимальной установки отсутствует или небезопасен')
    env = root / 'config/backend.env'
    require(env.is_file() and not env.is_symlink() and env.stat().st_mode & 0o077 == 0,
            'Закрытая конфигурация минимальной установки недоступна')
    checked = {}
    for name in ('http.sqlite', 'coordinator.sqlite'):
        database = root / 'db' / name
        require(database.is_file() and not database.is_symlink(), name + ' missing')
        # Настоящее SQLite-соединение к файлу без режима read-only immutable, чтобы были
        # видны зафиксированные страницы WAL. Это не блокирует записывающие процессы и
        # не создаёт резервную копию.
        connection = sqlite3.connect('file:' + urllib.parse.quote(str(database.resolve())) + '?mode=ro', uri=True, timeout=5)
        try:
            require(connection.execute('PRAGMA integrity_check').fetchone() == ('ok',), name + ' corrupt')
            require(connection.execute('PRAGMA foreign_key_check').fetchone() is None,
                    name + ' Нарушения внешних ключей')
        except sqlite3.Error as exc:
            raise AcceptanceError(name + ' не удалось прочитать') from exc
        finally:
            connection.close()
        checked[name] = 'целостность данных и внешние ключи проверены'
    for name in ('storage', 'factory', 'extensions', 'backups'):
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink(), name + ' missing')
        checked[name] = 'present'
    return checked


def verify_docs():
    count = 0
    for name in DOC_FILES:
        path = DOCS / name
        require(path.is_file(), 'Отсутствует документация: ' + name)
        content = path.read_text(encoding='utf-8')
        require(len(content) > 180, 'Пустой документ оператора: ' + name)
        count += 1
        # Относительные Markdown-ссылки в руководствах оператора должны разрешаться.
        # Абсолютные URL оставляются ссылками; на этом шаге ничего не скачивается и
        # сеть не читается.
        for dest in re.findall(r'(?<!!)\[[^\]]*\]\(([^)]+)\)', content):
            target = dest.split('#', 1)[0]
            if not target or target.startswith(('https://', 'http://', 'mailto:')):
                continue
            require((path.parent / target).exists(), name + ': отсутствует связанный файл ' + target)
            count += 1
    # Проверяйте реальное существование каждой точки входа, упомянутой в
    # эксплуатационных руководствах.
    for entry in ('scripts/install/production-deploy.py', 'scripts/install/minimal-install.py',
                  'scripts/operations/dr_03512.py', 'scripts/operations/db_upgrade_0457.py',
                  'scripts/operations/component_upgrade_0458.py',
                  'scripts/operations/chaos_0456.py', 'scripts/operations/restore_accept_0456.py',
                  'scripts/operations/observability_0459.py'):
        require((ROOT / entry).is_file(), 'Исполняемый файл оператора отсутствует: ' + entry)
        count += 1
    return {'checkedFiles': len(DOC_FILES), 'checkedLinksAndEntrypoints': count - len(DOC_FILES)}


def atomic_report(output, report):
    require(not output.exists() and not output.is_symlink(), 'Отказано в перезаписи существующего отчёта приёмки')
    require(output.parent.is_dir() and not output.parent.is_symlink(), 'Родительский каталог вывода отсутствует или небезопасен')
    fd, tmp = tempfile.mkstemp(prefix='.operator-04513-', dir=str(output.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        # Создание жёсткой ссылки возвращает EEXIST, даже если другой процесс создал
        # отчёт между начальной проверкой и публикацией. Никогда не перезаписывайте
        # доказательства.
        os.link(tmp, output)
        dir_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('docs-check', help="Разрешить операторские ссылки и пути к обязательным исполняемым файлам")
    live = sub.add_parser('live', help="Настоящая приёмка Backend/worker/БД только для чтения")
    live.add_argument('--mode', choices=CHECKS.keys(), required=True)
    live.add_argument('--url', required=True, help="Публичный HTTPS-адрес с проверенной CA либо /ready")
    live.add_argument('--version', default=VERSION.read_text().strip())
    live.add_argument('--project')
    live.add_argument('--env-file', type=Path)
    live.add_argument('--minimal-root', type=Path)
    live.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'docs-check':
            result = {'status': 'passed', 'scope': 'documentation-paths', **verify_docs()}
        else:
            require(re.fullmatch(r'0\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', args.version) is not None,
                    'Недопустимая версия')
            if args.mode == 'minimal':
                require(args.minimal_root is not None and not args.project and not args.env_file,
                        'Для минимального режима требуется только --minimal-root')
                values = operator_env(args.minimal_root / 'config/backend.env', expected_mode='single-node',
                                      expected_version=args.version, public_url=args.url, minimal=True)
                for key, relative in (
                    ('LAUNCHER_DATABASE_DSN', 'db/http.sqlite'),
                    ('LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH', 'db/coordinator.sqlite'),
                    ('LAUNCHER_STORAGE_LOCAL_PATH', 'storage'),
                ):
                    require(values.get(key) == str(args.minimal_root.resolve() / relative),
                            'Настроенное хранилище минимального режима не относится к выбранной установке')
                services = probe_minimal(args.minimal_root)
                repo, storage = 'sqlite', 'local'
            else:
                require(args.project and args.env_file and not args.minimal_root,
                        'Для Compose требуются только --project и --env-file')
                operator_env(args.env_file, expected_mode=args.mode, expected_version=args.version,
                             public_url=args.url)
                services = probe_compose(args.project, args.env_file, args.mode)
                repo, storage = 'postgres', 's3' if args.mode == 'network-ha' else 'local'
            public = ready(args.url, args.version, repo, storage)
            result = {'status': 'passed', 'scope': 'read-only-live-readiness',
                      'mode': args.mode, 'timestampUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                      'public': public, 'checks': services,
                      'limits': 'Переключение при сбое, восстановление из резервной копии, вход, подключение Minecraft и устойчивость нескольких узлов не проверялись'}
            atomic_report(args.report, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (AcceptanceError, OSError, sqlite3.Error) as exc:
        # Никогда не копируйте низкоуровневый текст исключения, где могут оказаться
        # секреты или пути.
        if isinstance(exc, AcceptanceError):
            reason = str(exc)
        else:
            reason = 'Проверка операционной системы или базы данных завершилась ошибкой'
        print(json.dumps({'status': 'failed', 'reason': reason}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

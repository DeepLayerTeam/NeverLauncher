#!/usr/bin/env python3
"""Независимая приёмка перехода со СТАРОЙ работающей установки на PostgreSQL на изолированном хосте.

`capture` работает на ИСХОДНОМ запущенном Backend. `verify` выполняется после переключения
оператором на ТОМ ЖЕ изолированном хосте. Приёмка невозможна по синтетической SQL-квитанции, одному
/ready или произвольному флагу PASS. Исходные базы утилита никогда не изменяет. Вывод имеет права
0600, поскольку снимки проектов могут содержать закрытые сведения.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sqlite3
import stat
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, parse_qs, unquote
from urllib.request import Request, build_opener, HTTPRedirectHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "operations"))
from sqlite_pg_cutover_0475 import (
    STAGES, CutoverError, private_file, storage_fingerprint, sqlite_backup,
    validate_sqlite_backup, write_secure, parse_env,
)

VERSION = '0.48.0'
SCHEMA = 'neverlauncher.live-independent-upgrade-0480-v1'
MAX_RESPONSE = 4 * 1024 * 1024

class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # учётные данные и bearer-токены никогда не должны передаваться при перенаправлениях

_HTTP_OPENER = build_opener(RejectRedirect)


class AcceptanceError(ValueError):
    pass


def require(value, detail):
    if not value:
        raise AcceptanceError(detail)


def json_file(path: Path):
    private_file(path)
    value = json.loads(path.read_text('utf-8'))
    require(isinstance(value, dict), 'Ожидался объект JSON')
    return value


def endpoint(base: str, path: str, *, method='GET', payload=None, token=None):
    parsed = urlsplit(base)
    require(parsed.scheme == 'https' or (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1', 'localhost')), 'HTTP разрешён только на локальном интерфейсе; для удалённого тестового окружения требуется HTTPS')
    require(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment and parsed.path in ('', '/'), 'Базовый URL не должен содержать учётные данные, путь или параметры запроса')
    raw = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
    headers = {'Accept': 'application/json'}
    if raw is not None:
        headers['Content-Type'] = 'application/json'
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = Request(base.rstrip('/') + path, data=raw, headers=headers, method=method)
    try:
        with _HTTP_OPENER.open(req, timeout=15) as response:
            require(response.status == 200, f'endpoint returned {response.status}: {path}')
            length = response.headers.get('Content-Length')
            if length is not None:
                require(int(length) <= MAX_RESPONSE, 'HTTP-ответ превышает ограничение приёмки')
            raw = response.read(MAX_RESPONSE + 1)
            require(len(raw) <= MAX_RESPONSE, 'Слишком большой HTTP-ответ')
            return json.loads(raw)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise AcceptanceError(f'Не удалось выполнить HTTP-запрос: {method} {path} ({type(exc).__name__})') from exc


def owner_login(base, credentials: Path):
    auth = json_file(credentials)
    require(isinstance(auth.get('email'), str) and '@' in auth['email'] and isinstance(auth.get('password'), str) and bool(auth['password']), 'Учётные данные владельца должны содержать адрес электронной почты и пароль')
    body = {'email': auth['email'], 'password': auth['password']}
    for optional in ('totp', 'recoveryCode', 'providerId'):
        if optional in auth:
            body[optional] = auth[optional]
    response = endpoint(base, '/api/v1/admin/login', method='POST', payload=body)
    require(isinstance(response, dict) and isinstance(response.get('token'), str) and len(response['token']) > 20, 'Владелец исходной версии не прошёл аутентификацию с реальной сессией')
    user = response.get('user') or {}
    require(isinstance(user, dict) and user.get('email', '').casefold() == auth['email'].casefold() and bool(user.get('id')), 'authenticated account differs from owner')
    return response['token'], {'id': user['id'], 'email': user['email'].casefold()}


def snapshot_api(base, token, project, profile, channel):
    p = '/api/v1/projects/' + quote(project, safe='')
    # Это реальные HTTP-операции Backend, не чтение фикстур. Одна проверка статуса
    # не заменяет сравнение настоящих доменных объектов.
    paths = [p, p + '/profiles', p + '/channels', p + '/versions',
             p + '/profiles/' + quote(profile, safe='') + '/revisions']
    rows = {}
    for path in paths:
        rows[path] = endpoint(base, path, token=token)
    # Проверяйте фактическое наличие ожидаемых проекта, профиля и канала.
    require(project in json.dumps(rows[p], sort_keys=True), 'project not returned from live Backend')
    require(profile in json.dumps(rows[p+'/profiles'], sort_keys=True), 'Ожидаемый профиль отсутствует')
    require(channel in json.dumps(rows[p+'/channels'], sort_keys=True), 'Ожидаемый канал отсутствует')
    return rows


def fingerprint_sqlite(source: Path, work: Path, kind: str):
    private_file(source)
    target = work / (kind + '-captured.sqlite')
    sqlite_backup(str(source), target)
    validate_sqlite_backup(target)
    with closing(sqlite3.connect(f'file:{target}?mode=ro', uri=True)) as db:
        tables = [x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        require(bool(tables), f'empty {kind} SQLite source')
        count = 0
        logical = hashlib.sha256()
        for line in db.iterdump():
            logical.update(line.encode('utf-8'))
            logical.update(b'\n')
        for table in tables:
            name = '"' + table.replace('"', '""') + '"'
            count += db.execute('SELECT count(*) FROM ' + name).fetchone()[0]
    return {'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'tables': len(tables), 'rows': count, 'logicalSha256': logical.hexdigest()}


def running_version(base):
    response = endpoint(base, '/api/v1/status')
    require(isinstance(response, dict) and isinstance(response.get('version'), str), 'В Backend отсутствует рабочий метод получения версии')
    return response['version']


def capture(a):
    require(not a.output.exists(), 'refusing to replace baseline from original installation')
    require(a.output.parent.is_dir() and not a.output.parent.is_symlink() and a.output.parent.stat().st_mode & 0o077 == 0, 'Требуется закрытый выходной каталог с правами 0700')
    current = running_version(a.base_url)
    require(re.fullmatch(r'0\.(?:45\.14|46\.[0-3]|47\.[0-8])', current) and current == a.old_version, 'old Backend version differs from claimed installed baseline')
    token, owner = owner_login(a.base_url, a.owner_credentials)
    rows = snapshot_api(a.base_url, token, a.project, a.profile, a.channel)
    sources = {}
    for kind, path in [('core',a.core_db),('http',a.http_db),('coordinator',a.coordinator_db)]:
        require(path is not None, f'{kind} SQLite source required for GA')
        sources[kind] = fingerprint_sqlite(path, a.output.parent, kind)
    storage_sha, n, size = storage_fingerprint(a.storage)
    require(n > 0, 'Тестовый проект для финальной приёмки должен содержать реальные сохранённые объекты')
    result = {'schema': SCHEMA, 'version': VERSION, 'originalVersion': current, 'project':a.project, 'profile':a.profile, 'channel':a.channel,
              'owner': owner, 'api': rows, 'sqlite': sources,
              'storage': {'sha256': storage_sha, 'objects': n, 'bytes': size}}
    write_secure(a.output, (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    return result


def postgres_live_probe(path: Path, project: str, owner: str):
    # Запрашивайте настоящую БД, указанную в EnvironmentFile службы Backend systemd. Не
    # принимайте произвольный JSON с утверждением, что PostgreSQL проверен.
    conf = parse_env(path)
    require(conf.get('LAUNCHER_REPOSITORY_DRIVER') == 'postgres' and conf.get('LAUNCHER_SQL_DRIVER') == 'pgx', 'Развёрнутый Backend не настроен на PostgreSQL')
    dsn = conf.get('LAUNCHER_DATABASE_DSN', '')
    url = urlsplit(dsn)
    require(url.scheme in ('postgres','postgresql') and url.hostname and url.path not in ('', '/'), 'Некорректная строка подключения к PostgreSQL в развёрнутом окружении')
    require(not url.fragment, 'Небезопасный фрагмент строки подключения PostgreSQL')
    params = parse_qs(url.query, strict_parsing=True)
    require(set(params) <= {'sslmode', 'sslrootcert', 'sslcert', 'sslkey', 'connect_timeout'} and all(len(v)==1 for v in params.values()), 'Неподдерживаемый параметр подключения PostgreSQL')
    env = os.environ.copy()
    # Не допускайте утечки развёрнутого пароля PostgreSQL через argv, журналы или отчёты.
    for key in ('PGHOST','PGPORT','PGUSER','PGDATABASE','PGPASSWORD','PGSSLMODE','PGSSLROOTCERT','PGSSLCERT','PGSSLKEY','PGCONNECT_TIMEOUT','PGSERVICE','PGSERVICEFILE','PGOPTIONS'):
        env.pop(key, None)
    env.update(PGHOST=url.hostname, PGPORT=str(url.port or 5432), PGUSER=unquote(url.username or ''),
               PGDATABASE=unquote(url.path.lstrip('/')))
    if url.password:
        env['PGPASSWORD'] = unquote(url.password)
    for key, value in params.items():
        env['PG'+key.upper()] = value[0]
    sql = "SELECT CASE WHEN (SELECT count(*) FROM projects WHERE id=:'project_id')=1 AND (SELECT count(*) FROM users WHERE id=:'owner_id')=1 THEN 'accepted' ELSE 'rejected' END;\n"
    try:
        completed = subprocess.run(['psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1',
                                    '-v','project_id='+project, '-v','owner_id='+owner],
                                   input=sql, text=True, capture_output=True, env=env, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError('Не удалось независимо проверить развёрнутую PostgreSQL через psql') from exc
    require(completed.returncode == 0 and completed.stdout.strip() == 'accepted', 'Прямой запрос владельца или проекта к развёрнутому PostgreSQL завершился ошибкой')


def verify(a):
    baseline = json_file(a.baseline)
    require(baseline.get('schema') == SCHEMA and baseline.get('version') == VERSION, 'Некорректная версия исходной сборки')
    require(re.fullmatch(r'0\.(?:45\.14|46\.[0-3]|47\.[0-8])', baseline.get('originalVersion','')), 'baseline was not captured from a supported older Backend')
    require(running_version(a.base_url) == VERSION, 'Фактически обновлённый Backend не работает на версии 0.48.0')
    for key in ('project','profile','channel'):
        require(baseline.get(key) == getattr(a, key), 'Не совпадает идентификатор проекта исходной сборки')
    token, owner = owner_login(a.base_url, a.owner_credentials)
    require(owner == baseline['owner'], 'При миграции изменились идентификатор или почта исходного владельца')
    require(snapshot_api(a.base_url, token, a.project, a.profile, a.channel) == baseline['api'], 'После обновления изменилось содержимое проекта, профиля, канала или выпуска')
    state = json_file(a.operator_work / 'state.json')
    require(state.get('completed') == list(STAGES) and state.get('cutoverSupported') is True and state.get('writeBoundaryCrossed') is True and not state.get('rolledBack'), 'Оператор не завершил разрешённое переключение на PostgreSQL')
    receipt = (state.get('receipts') or {}).get('verify') or {}
    require(receipt.get('verified') is True and receipt.get('readyForBackendCutover') is True and receipt.get('ownerId') == owner['id'], 'Квитанция владельца или переключения репозитория PostgreSQL не проверена')
    # Backend сам должен переключиться; устаревший SQLite Backend с теми
    # же объектами не означает успешную миграцию.
    postgres_live_probe(a.backend_env, a.project, owner['id'])
    source_sha, n, size = storage_fingerprint(a.storage)
    require(baseline['storage'] == {'sha256': source_sha, 'objects': n, 'bytes': size}, 'После обновления изменилось исходное локальное хранилище')
    require(a.target_storage is not None and a.target_storage.resolve() != a.storage.resolve(), 'Для проверки чтения из PostgreSQL требуется независимое целевое хранилище')
    target_sha, target_n, target_size = storage_fingerprint(a.target_storage)
    require(baseline['storage'] == {'sha256': target_sha, 'objects': target_n, 'bytes': target_size}, 'Локальное хранилище целевого PostgreSQL побайтово не совпадает с источником')
    for kind, path in [('core',a.core_db),('http',a.http_db),('coordinator',a.coordinator_db)]:
        require(path is not None, 'Отсутствует исходная база SQLite')
        old = a.baseline.parent / (kind + '-captured.sqlite')
        private_file(old)
        require(hashlib.sha256(old.read_bytes()).hexdigest() == baseline['sqlite'][kind]['sha256'], f'captured {kind} SQLite baseline changed')
        validate_sqlite_backup(path)
        with closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True)) as db:
            logical = hashlib.sha256()
            for line in db.iterdump():
                logical.update(line.encode('utf-8')); logical.update(b'\n')
        require(logical.hexdigest() == baseline['sqlite'][kind]['logicalSha256'], f'original {kind} SQLite data changed unexpectedly')
    require(not a.output.exists(), 'Отказ от перезаписи квитанции реальной приёмки')
    output = {'schema':'neverlauncher.live-upgrade-acceptance-0480-v1', 'version':VERSION,
              'sourceBaselineSHA256': hashlib.sha256(a.baseline.read_bytes()).hexdigest(),
              'project': a.project, 'ownerId': owner['id'], 'ownerLogin': 'actual-session',
              'apiEquivalent': True, 'sourceSQLiteVerified': True,
              'storageVerified': True, 'cutoverVerified': True, 'backendPostgresVerified': True}
    write_secure(a.output, (json.dumps(output, sort_keys=True, indent=2)+'\n').encode())
    return output


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('capture','verify'))
    p.add_argument('--base-url', required=True)
    p.add_argument('--owner-credentials', type=Path, required=True)
    p.add_argument('--old-version', default='')
    p.add_argument('--project', required=True)
    p.add_argument('--profile', required=True)
    p.add_argument('--channel', required=True)
    p.add_argument('--core-db', type=Path, required=True)
    p.add_argument('--http-db', type=Path, required=True)
    p.add_argument('--coordinator-db', type=Path, required=True)
    p.add_argument('--storage', type=Path, required=True)
    p.add_argument('--target-storage', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--baseline', type=Path)
    p.add_argument('--operator-work', type=Path)
    p.add_argument('--backend-env', type=Path)
    a = p.parse_args(argv)
    try:
        # Обязательны точные исходный эталон и фактические файлы оператора после переключения.
        if a.action == 'capture':
            capture(a)
        else:
            require(a.baseline and a.operator_work and a.backend_env, 'Отсутствуют независимо собранные свидетельства источника, оператора или Runtime')
            verify(a)
        print(f'0.48.0 live {a.action} completed')
        return 0
    except (OSError, ValueError, CutoverError, sqlite3.DatabaseError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f'Приёмка реальной среды 0.48.0 отклонена: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

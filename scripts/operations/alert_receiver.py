#!/usr/bin/env python3
"""Независимое подтверждение доставки вебхуков Alertmanager при физических HA-учениях.

Слушать ТОЛЬКО loopback за отдельно управляемым проверенным HTTPS-прокси. Для POST Alertmanager и
GET рецензента использовать разные bearer-токены с правами файлов 0600. Успешный GET читает
*устойчиво сохранённое* событие, ранее пришедшее по настоящему вебхуку; запрос собственного /alerts
API Alertmanager не считается доставкой.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import stat
import tempfile

SCHEMA = 'neverlauncher.physical-alert-delivery/0.52.10'
FINGERPRINT = re.compile(r'[a-f0-9]{16,64}\Z')
ALERT = re.compile(r'NeverLauncher[A-Za-z0-9]{2,80}\Z')

class Error(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Error(reason)

def read_secret(path):
    p = Path(path)
    require(p.is_absolute() and not p.is_symlink() and not any(q.is_symlink() for q in p.parents),
            'Токен должен быть задан абсолютным путём, не являющимся символической ссылкой')
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                (stat.S_IMODE(st.st_mode) & 0o077) == 0 and 32 <= st.st_size <= 4096,
                'Небезопасный файл токена')
        token = os.read(fd, 4097).strip()
        require(32 <= len(token) <= 4096 and all(33 <= x <= 126 for x in token),
                'Небезопасный токен доступа')
        return token
    finally:
        os.close(fd)

def unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, 'повторяющееся поле события')
        obj[key] = value
    return obj

def accept_alert(payload, expected):
    require(isinstance(payload, dict) and payload.get('status') == 'firing',
            'Ожидался реальный webhook Alertmanager с активным оповещением')
    alerts = payload.get('alerts')
    require(isinstance(alerts, list) and 1 <= len(alerts) <= 128, 'Недопустимое количество оповещений Alertmanager')
    matching = []
    for entry in alerts:
        if not isinstance(entry, dict) or entry.get('status') != 'firing' or \
                (entry.get('labels') or {}).get('alertname') != expected:
            continue
        fingerprint = entry.get('fingerprint')
        require(isinstance(fingerprint, str) and FINGERPRINT.fullmatch(fingerprint),
                'Недопустимый отпечаток оповещения')
        try:
            start = datetime.fromisoformat(entry['startsAt'].replace('Z', '+00:00'))
            require(start.tzinfo is not None and start <= datetime.now(timezone.utc),
                    'Некорректное время начала срабатывания оповещения')
        except (KeyError, AttributeError, TypeError, ValueError) as exc:
            raise Error('Некорректная временная метка события Alertmanager') from exc
        matching.append((fingerprint, start))
    require(len(matching) == 1, 'Требуется одно однозначно заданное ожидаемое оповещение')
    fingerprint, start = matching[0]
    return {'schema': SCHEMA, 'alertname': expected, 'fingerprint': fingerprint,
            'startedAt': start.astimezone(timezone.utc).isoformat(),
            'receivedAt': datetime.now(timezone.utc).isoformat(), 'status': 'delivered'}

def validate_dir(folder):
    folder = Path(folder)
    require(folder.is_absolute() and folder.is_dir() and not folder.is_symlink() and
            folder.stat().st_uid == os.geteuid() and stat.S_IMODE(folder.stat().st_mode) & 0o077 == 0,
            'Каталог получателя должен иметь закрытые права 0700')
    return folder

def store(folder, result):
    folder = validate_dir(folder)
    path = folder / 'latest.json'
    require(not path.is_symlink(), 'Журнал получателя является символьной ссылкой')
    content = (json.dumps(result, sort_keys=True) + '\n').encode()
    fd, temp = tempfile.mkstemp(prefix='.alert-05210-', dir=folder)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        descriptor = os.open(folder, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def latest(folder):
    validate_dir(folder)
    path = folder / 'latest.json'
    require(not path.is_symlink() and path.is_file(), 'Нет оповещения, доставленного по независимому каналу')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) & 0o077 == 0 and 0 < st.st_size <= 8192,
                'Небезопасный файл подтверждения')
        data = json.loads(os.read(fd, 8193), object_pairs_hook=unique)
        require(isinstance(data, dict) and data.get('schema') == SCHEMA and
                data.get('status') == 'delivered', 'Некорректное сохранённое подтверждение оповещения')
        return data
    finally:
        os.close(fd)

def make_handler(folder, alert, webhook_token, reader_token):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'NeverLauncher-Alert-Receiver/0.52.10'
        sys_version = ''
        def log_message(self, format, *args):
            # Не журналируйте заголовки Authorization, исходные адреса и метки событий.
            return
        def check(self, expected):
            raw = self.headers.get('Authorization', '').encode('utf-8', 'replace')
            return hmac.compare_digest(raw, b'Bearer ' + expected)
        def reply(self, status, data):
            raw = (json.dumps(data, sort_keys=True) + '\n').encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_POST(self):
            if self.path != '/webhook' or not self.check(webhook_token):
                self.reply(403, {'status':'rejected'})
                return
            try:
                n = int(self.headers.get('Content-Length', '0'))
                require(0 < n <= 65536, 'Превышен допустимый размер webhook')
                raw = self.rfile.read(n)
                require(len(raw) == n, 'Webhook усечён')
                data = json.loads(raw, object_pairs_hook=unique)
                report = accept_alert(data, alert)
                store(folder, report)
                self.reply(200, {'status':'stored'})
            except (Error, ValueError, UnicodeError, OSError):
                self.reply(422, {'status':'rejected'})
        def do_GET(self):
            if self.path != '/events/latest' or not self.check(reader_token):
                self.reply(403, {'status':'rejected'})
                return
            try:
                self.reply(200, latest(folder))
            except (Error, ValueError, OSError):
                self.reply(404, {'status':'unavailable'})
    return Handler

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=18871)
    p.add_argument('--directory', required=True)
    p.add_argument('--expected-alert', required=True)
    p.add_argument('--webhook-token-file', required=True)
    p.add_argument('--reader-token-file', required=True)
    args = p.parse_args()
    try:
        require(1024 <= args.port <= 65535 and ALERT.fullmatch(args.expected_alert),
                'Некорректный порт или ожидаемое оповещение')
        folder = validate_dir(args.directory)
        webhook, reader = read_secret(args.webhook_token_file), read_secret(args.reader_token_file)
        require(webhook != reader, 'Для webhook и чтения результатов должны использоваться разные токены Bearer')
        server = ThreadingHTTPServer(('127.0.0.1', args.port),
                 make_handler(folder, args.expected_alert, webhook, reader))
        server.serve_forever(poll_interval=.25)
    except (OSError, Error):
        return 3
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

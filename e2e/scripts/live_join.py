#!/usr/bin/env python3
"""Наблюдение настоящей совместимости мультиплеера Minecraft с совпадающими версиями.

Запускается временный выделенный сервер, привязанный к localhost, из проверенного серверного JAR
Mojang или дистрибутива серверного загрузчика с независимо закреплённым SHA-256. Одного клиентского
процесса/тайм-аута недостаточно для шлюза. Серверные наблюдения RCON и входа в консоли фиксируются,
когда игровой клиент действительно онлайн.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from staged_matching_0344 import MatchingServer, JOIN, CRASH, player_online, parse_gametime, file_sha256

SHA = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[a-z0-9][a-z0-9._-]{2,95}\Z')
PLAYER = 'NL_Cert_Client'  # Фактическое имя пользователя в совместимом запускателе Runtime.


def run_binding():
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', 'local')
    return {
        'sourceCommit': os.environ.get('GITHUB_SHA', 'local'),
        'ciRunId': os.environ.get('GITHUB_RUN_ID', 'local'),
        'ciRunAttempt': int(attempt) if attempt.isdecimal() else 0,
    }


def require(value, message):
    if not value:
        raise RuntimeError(message)


def read_json(path):
    with open(path, 'r', encoding='utf-8') as stream:
        return json.load(stream, object_pairs_hook=no_duplicates)


def no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, 'Повторяющийся ключ JSON: ' + k)
        out[k] = v
    return out


def atomically_write(path, payload):
    path = Path(path)
    contents = (json.dumps(payload, sort_keys=True, indent=2) + '\n').encode()
    # Запрещайте замену заранее созданной вредоносной квитанции и следование символическим ссылкам.
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def load_pinned_bundle(args):
    if args.loader == 'vanilla' and not args.pins:
        return '', '', '', ''
    require(bool(args.pins), 'dedicated loader/legacy server bundle pins required; no bundle = BLOCKED')
    manifest = read_json(Path(args.pins).resolve())
    require(manifest.get('schema') == 'neverlauncher.compatibility-server/0.52.4', 'Схема закреплённых параметров сервера не совпадает')
    targets = manifest.get('targets')
    require(type(targets) is dict, 'Отсутствуют целевые параметры закрепления сервера')
    entry = targets.get(args.target)
    require(type(entry) is dict, 'Для целевой платформы нет одобренного дистрибутива выделенного сервера: ' + args.target)
    require(all(entry.get(k) == getattr(args, attribute) for k, attribute in
                (('loader', 'loader'), ('minecraft', 'minecraft'))), 'Версия или загрузчик серверного пакета не соответствует целевому окружению')
    # Закреплённая версия загрузчика — РАЗРЕШЁННАЯ версия установленного клиентского загрузчика, а не latest.
    require(entry.get('loaderVersion', '') == args.loader_version, 'Версия загрузчика серверного пакета не совпадает')
    sha = entry.get('sha256')
    require(type(sha) is str and SHA.fullmatch(sha), 'Некорректная закреплённая контрольная сумма SHA-256 пакета')
    name = entry.get('file')
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip', name) and '..' not in name,
            'Путь пакета должен содержать только закреплённое имя ZIP-файла')
    require(bool(args.bundle_dir), 'Требуется каталог серверного пакета')
    directory = Path(args.bundle_dir).resolve(strict=True)
    path = directory / name
    require(path.is_file() and not path.is_symlink() and path.resolve().parent == directory,
            'Закреплённый серверный пакет отсутствует или небезопасен')
    require(path.stat().st_size <= 3 * 1024 * 1024 * 1024, 'Серверный пакет превышает ограничение размера')
    require(file_sha256(path) == sha, 'ZIP выделенного сервера не соответствует закреплённой сумме SHA-256')
    server_entry = entry.get('serverEntry', '')
    require(type(server_entry) is str and (not server_entry or re.fullmatch(r'[a-zA-Z0-9._-]{1,80}', server_entry)),
            'Некорректная закреплённая запись сервера')
    return str(path), sha, server_entry, file_sha256(Path(args.pins))


def serve(args):
    require(ID.fullmatch(args.target) is not None, 'invalid target ID')
    require(args.loader in ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge'), 'unknown loader')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,63}', args.minecraft) is not None, 'Некорректная версия Minecraft')
    runtime = Path(args.runtime).resolve(strict=True)
    require(runtime.is_dir() and not runtime.is_symlink(), 'Небезопасный каталог Runtime')
    for name in ('live-server-ready.json', 'live-server-witness.json', 'live-server-stopped.json', 'live-server-stop.request', 'live-join.json'):
        require(not (runtime / name).exists(), 'Устаревшее свидетельство реального подключения: ' + name)
    bundle, sha, server_entry, pins_sha = load_pinned_bundle(args)
    server = MatchingServer(runtime, args.java, args.cli, args.minecraft, args.loader,
                            args.loader_version, bundle=bundle, bundle_sha=sha,
                            server_entry=server_entry, require_bridge=False)
    running = True
    normal_stop = False

    def stop(_signal, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    if hasattr(signal, 'SIGINT'):
        signal.signal(signal.SIGINT, stop)
    try:
        server.prepare().start(timeout=200)
        print('[live-join] native dedicated server booted and RCON/game ticks verified', flush=True)
        atomically_write(runtime / 'live-server-ready.json', {
            'schema': 'neverlauncher.compatibility-server-ready/0.52.4',
            **run_binding(),
            'targetId': args.target, 'minecraftVersion': args.minecraft,
            'loader': args.loader, 'loaderVersion': args.loader_version,
            'port': server.port, 'serverPid': server.process.pid,
            'serverArtifactSha256': server.artifact_sha, 'pinManifestSha256': pins_sha,
        })
        # Наблюдайте сервер и RCON, пока реальный JVM-клиент ещё работает. Последующий таймаут
        # клиента не может создать это одновременное доказательство задним числом.
        started = time.monotonic()
        while running and time.monotonic() - started < args.monitor_seconds:
            if (runtime / 'live-server-stop.request').exists():
                normal_stop = True
                break
            if server.process.poll() is not None:
                raise RuntimeError('Реальный выделенный сервер Minecraft завершил работу')
            log = server.log_text()
            if PLAYER in JOIN.findall(log):
                try:
                    if player_online(server.rcon.query('list'), PLAYER):
                        before = parse_gametime(server.rcon.query('time query gametime'))
                        time.sleep(1.2)
                        after = parse_gametime(server.rcon.query('time query gametime'))
                        if after > before and player_online(server.rcon.query('list'), PLAYER):
                            print('[live-join] real player observed online with advancing ticks', flush=True)
                            atomically_write(runtime / 'live-server-witness.json', {
                                'schema': 'neverlauncher.compatibility-join-witness/0.52.4',
                                **run_binding(),
                                'targetId': args.target, 'minecraftVersion': args.minecraft,
                                'loader': args.loader, 'loaderVersion': args.loader_version,
                                'username': PLAYER, 'serverPid': server.process.pid,
                                'port': server.port, 'serverArtifactSha256': server.artifact_sha,
                                'joinedFromServerLog': True, 'playerOnlineViaRcon': True,
                                'tickBefore': before, 'tickAfter': after,
                                'joinedAtUnix': int(time.time()),
                            })
                            # Оставляйте сервер работающим для независимой проверки, затем
                            # корректно завершайте его при срабатывании ловушки очистки shell.
                            while running and server.process.poll() is None:
                                if (runtime / 'live-server-stop.request').exists():
                                    normal_stop = True
                                    break
                                time.sleep(.25)
                            break
                except (OSError, ValueError, RuntimeError, PermissionError, ConnectionError):
                    pass
            time.sleep(.35)
        else:
            if running:
                raise RuntimeError('Вход в реальный сервер Minecraft не подтверждён за отведённое время')
    finally:
        # Успешного наблюдения недостаточно, если выделенная игровая JVM завершилась до окончания
        # клиентского запуска у вызывающей стороны. Подтверждайте только штатное завершение.
        healthy_at_stop = (normal_stop and server.process is not None
                           and server.process.poll() is None
                           and (runtime / 'live-server-witness.json').is_file())
        if healthy_at_stop:
            # Попросите НАСТОЯЩУЮ серверную JVM сохранить данные и завершиться через аутентифицированный
            # RCON; убитый процесс или аварийно завершившийся сервер не должны получать PASS.
            try:
                server.rcon.query('stop')
            except (OSError, ValueError, RuntimeError, PermissionError, ConnectionError):
                pass  # При штатной остановке сервера сокет RCON может закрыться.
            try:
                healthy_at_stop = server.process.wait(timeout=30) == 0
            except __import__('subprocess').TimeoutExpired:
                healthy_at_stop = False
        server.close()
        if healthy_at_stop:
            atomically_write(runtime / 'live-server-stopped.json', {
                'schema': 'neverlauncher.compatibility-server-stopped/0.52.4',
                **run_binding(),
                'targetId': args.target, 'minecraftVersion': args.minecraft,
                'loader': args.loader, 'loaderVersion': args.loader_version,
                'serverPid': server.process.pid, 'serverPort': server.port,
                'serverArtifactSha256': server.artifact_sha,
                'serverLogSha256': file_sha256(runtime / 'matching-server.log'),
                'stoppedAfterLiveWitness': True,
            })
    require(normal_stop, 'Реальный сервер не получил запрос на корректную остановку')
    return 0


def verify(args):
    runtime = Path(args.runtime).resolve(strict=True)
    ready = read_json(runtime / 'live-server-ready.json')
    witness = read_json(runtime / 'live-server-witness.json')
    stopped = read_json(runtime / 'live-server-stopped.json')
    cert_path = runtime / (args.loader + '-certification.json')
    cert = read_json(cert_path)
    log_path = runtime / 'matching-server.log'
    log = log_path.read_text(encoding='utf-8', errors='replace')
    require(ready.get('schema') == 'neverlauncher.compatibility-server-ready/0.52.4', 'Несовпадение схемы готовности')
    require(witness.get('schema') == 'neverlauncher.compatibility-join-witness/0.52.4', 'Несовпадение схемы свидетельства')
    for label, doc in (('ready', ready), ('witness', witness), ('stopped', stopped)):
        require(all(doc.get(k) == v for k, v in run_binding().items()),
                label + ': повторно использовано исходное свидетельство коммита, запуска или попытки CI')
    for label, doc in (('ready', ready), ('witness', witness)):
        require(doc.get('targetId') == args.target and doc.get('minecraftVersion') == args.minecraft and
                doc.get('loader') == args.loader and doc.get('loaderVersion') == args.loader_version,
                label + ': идентификаторы клиента и сервера не совпадают')
    for field in ('serverPid', 'port', 'serverArtifactSha256'):
        require(ready.get(field) == witness.get(field), 'Изменился идентификатор сервера-свидетеля: ' + field)
    require(stopped.get('schema') == 'neverlauncher.compatibility-server-stopped/0.52.4'
            and stopped.get('stoppedAfterLiveWitness') is True
            and stopped.get('targetId') == args.target
            and stopped.get('minecraftVersion') == args.minecraft
            and stopped.get('loader') == args.loader
            and stopped.get('loaderVersion') == args.loader_version
            and stopped.get('serverPid') == ready.get('serverPid')
            and stopped.get('serverPort') == ready.get('port')
            and stopped.get('serverArtifactSha256') == ready.get('serverArtifactSha256')
            and stopped.get('serverLogSha256') == file_sha256(log_path),
            'Сервер завершился до штатной остановки или изменился его консольный журнал')
    require(not CRASH.search(log), 'Во время запуска произошёл сбой выделенного игрового сервера')
    require(PLAYER in JOIN.findall(log) and witness.get('username') == PLAYER and
            witness.get('joinedFromServerLog') is True and witness.get('playerOnlineViaRcon') is True,
            'Консоль сервера или RCON не подтвердили реальное подключение клиента')
    require(type(witness.get('tickBefore')) is int and type(witness.get('tickAfter')) is int and
            witness['tickAfter'] > witness['tickBefore'], 'Время в реальном мире Minecraft не изменилось')
    require(cert.get('status') == 'passed' and cert.get('matchingServer') == '127.0.0.1' and
            cert.get('matchingServerPort') == ready.get('port') and
            (cert.get('success') is True or cert.get('timedOut') is True),
            'Проверенный клиент не был направлен на фактический выделенный сервер')
    require(args.profile == cert.get('minecraftVersion'), 'Профиль клиента не соответствует установленному профилю загрузчика')
    require(cert.get('requiredJavaMajor') == args.java_major and
            cert.get('detectedJavaMajor') == args.java_major and
            type(cert.get('classpathEntries')) is int and cert['classpathEntries'] > 0,
            'Запуск JVM или загрузчика не прошёл проверку')
    atomically_write(runtime / 'live-join.json', {
        'schema': 'neverlauncher.compatibility-live-join/0.52.4',
        **run_binding(),
        'status': 'passed', 'targetId': args.target,
        'minecraftVersion': args.minecraft, 'loader': args.loader,
        'loaderVersion': args.loader_version, 'profileId': args.profile,
        'javaMajor': args.java_major, 'serverPort': ready['port'],
        'serverArtifactSha256': ready['serverArtifactSha256'],
        'serverProcessId': ready['serverPid'], 'username': PLAYER,
        'serverLogSha256': file_sha256(log_path),
        'clientCertificationSha256': file_sha256(cert_path),
        'witnessSha256': file_sha256(runtime / 'live-server-witness.json'),
        'serverStoppedSha256': file_sha256(runtime / 'live-server-stopped.json'),
        'playerJoined': True, 'playerOnlineViaRcon': True,
        'worldTicksAdvanced': True,
    })
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('serve', 'verify'):
        p = sub.add_parser(command)
        p.add_argument('--runtime', required=True)
        p.add_argument('--target', required=True)
        p.add_argument('--minecraft', required=True)
        p.add_argument('--loader', choices=['vanilla', 'fabric', 'quilt', 'forge', 'neoforge'], required=True)
        p.add_argument('--loader-version', default='')
    serve_p = sub.choices['serve']
    serve_p.add_argument('--java', required=True)
    serve_p.add_argument('--cli', required=True)
    serve_p.add_argument('--pins', default='')
    serve_p.add_argument('--bundle-dir', default='')
    serve_p.add_argument('--monitor-seconds', type=int, default=240)
    verify_p = sub.choices['verify']
    verify_p.add_argument('--profile', required=True)
    verify_p.add_argument('--java-major', type=int, required=True)
    args = parser.parse_args()
    try:
        return serve(args) if args.command == 'serve' else verify(args)
    except (RuntimeError, OSError, ValueError, KeyError) as err:
        print('[live-join-0524] BLOCKED: ' + str(err), file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())

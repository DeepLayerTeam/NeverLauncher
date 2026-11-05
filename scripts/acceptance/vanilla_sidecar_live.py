#!/usr/bin/env python3
"""Проверка работающего Vanilla 1.21.1 и производственного sidecar на *живом Linux-хосте*.

Проверка обращается к настоящему сокету состояния Minecraft и защищённому паролем локальному RCON,
изучает запущенный Java-процесс sidecar и повторно вычисляет хеш его JAR. Подменный сервер не
запускается, JSON состояния не принимается за доказательство.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import time

VERSION = Path(__file__).resolve().parents[2].joinpath('VERSION').read_text().strip()
HEX = re.compile(r'[a-f0-9]{64}\Z')

class Blocked(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise Blocked(message)

def file_hash(path):
    require(path.is_file() and not path.is_symlink(), 'Физический файл отсутствует или небезопасен')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for piece in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(piece)
    return h.hexdigest()

def recv_exact(sock, size):
    require(0 <= size <= 1048576, 'Недопустимый размер сетевых данных')
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size-len(chunks))
        require(bool(part), 'Усечённый ответ Minecraft/RCON')
        chunks.extend(part)
    return bytes(chunks)

def varint(value):
    require(0 <= value <= 0x7fffffff, 'Недопустимое значение Minecraft VarInt')
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)

def read_varint(sock):
    result = 0
    for shift in range(0, 35, 7):
        n = recv_exact(sock, 1)[0]
        result |= (n & 127) << shift
        if n & 128 == 0:
            require(result <= 0x7fffffff, 'Переполнение Minecraft VarInt')
            return result
    raise Blocked('Слишком длинное значение VarInt Minecraft')

def status(host, port, expected_minecraft):
    require(host in ('127.0.0.1', '::1'), 'Запрос состояния должен использовать локальный интерфейс сервера')
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        host_raw = host.encode('ascii')
        handshake = varint(0) + varint(767) + varint(len(host_raw)) + host_raw + struct.pack('>H', port) + varint(1)
        sock.sendall(varint(len(handshake)) + handshake + b'\x01\x00')
        size = read_varint(sock)
        require(2 <= size <= 65536, 'Недопустимый пакет состояния Minecraft')
        frame_id = read_varint(sock)
        size_json = read_varint(sock)
        require(frame_id == 0 and 0 < size_json <= 65536 and size_json <= size, 'Недопустимый ответ состояния Minecraft')
        raw = recv_exact(sock, size_json)
        reply = json.loads(raw)
        version = reply.get('version', {})
        players = reply.get('players', {})
        require(type(version) is dict and version.get('name') == expected_minecraft and
                type(version.get('protocol')) is int and version['protocol'] > 0 and
                type(players) is dict and type(players.get('max')) is int,
                'Неверный реальный сервер, редакция или версия Minecraft')
        return {'minecraft': version['name'], 'protocol': version['protocol'], 'playersMax': players['max']}

def rcon_packet(sock, request_id, command_type, body):
    raw = body.encode('utf-8')
    require(len(raw) <= 8192, 'Слишком длинные данные RCON')
    payload = struct.pack('<ii', request_id, command_type) + raw + b'\0\0'
    sock.sendall(struct.pack('<i', len(payload)) + payload)
    length = struct.unpack('<i', recv_exact(sock, 4))[0]
    require(10 <= length <= 1048576, 'Недопустимая длина ответа RCON')
    data = recv_exact(sock, length)
    rid, _ = struct.unpack('<ii', data[:8])
    require(data[-2:] == b'\0\0', 'Недопустимый терминатор ответа RCON')
    return rid, data[8:-2].decode('utf-8', errors='strict')

def rcon(host, port, password, command):
    require(host in ('127.0.0.1', '::1'), 'RCON должен прослушивать только локальный интерфейс')
    require(bool(password) and len(password) >= 12, 'Требуются закрытые учётные данные RCON')
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        authid, _ = rcon_packet(sock, 39715, 3, password)
        require(authid == 39715, 'Настоящий сервер Minecraft отклонил авторизацию RCON')
        rid, result = rcon_packet(sock, 39716, 2, command)
        require(rid == 39716 and bool(result.strip()), 'Реальная команда RCON завершилась ошибкой')
        return result

def inspect_process(pid, jar, expected_sha):
    require(os.name == 'posix' and Path('/proc').is_dir(), 'Требуется нативная проверка процессов Linux')
    require(type(pid) is int and pid > 1, 'Требуется идентификатор PID реального вспомогательного процесса JVM')
    cmdfile = Path('/proc') / str(pid) / 'cmdline'
    require(cmdfile.is_file(), 'Вспомогательный процесс JVM не запущен')
    args = cmdfile.read_bytes().split(b'\x00')
    require(args and Path(os.fsdecode(args[0])).name.startswith('java'), 'Вспомогательный процесс не является Java-процессом')
    # Проверяйте путь JAR, переданный JVM, а не случайное совпадение подстроки.
    found = [os.fsdecode(args[i+1]) for i,a in enumerate(args[:-1]) if a == b'-jar']
    require(len(found) == 1 and Path(found[0]).resolve() == jar.resolve(), 'Запущен другой исполняемый JAR вспомогательной службы')
    require(file_hash(jar) == expected_sha, 'Запущенный файл вспомогательного процесса отличается от проверенного JAR выпуска')

def verify(cfg, *, sleep=time.sleep):
    required = {'sidecarPid', 'sidecarJar', 'sidecarSha256', 'sidecarLog', 'serverLog',
                'serverDir', 'minecraftPort', 'rconPort', 'minecraftVersion'}
    require(type(cfg) is dict and set(cfg) == required, 'Конфигурация реального Vanilla-хоста заполнена не полностью')
    require(cfg['minecraftVersion'] == '1.21.1', 'Несовпадение области действия целевой платформы Vanilla')
    require(isinstance(cfg['sidecarSha256'], str) and HEX.fullmatch(cfg['sidecarSha256']), 'Недопустимая контрольная сумма вспомогательного процесса')
    jar, server_dir = Path(cfg['sidecarJar']), Path(cfg['serverDir'])
    require(jar.is_absolute() and server_dir.is_absolute(), 'Требуются абсолютные пути к вспомогательному процессу и серверу')
    inspect_process(cfg['sidecarPid'], jar, cfg['sidecarSha256'])
    props = server_dir / 'server.properties'
    require(props.is_file() and not props.is_symlink(), 'Требуется настоящий файл Vanilla server.properties')
    settings = dict(line.split('=', 1) for line in props.read_text().splitlines() if '=' in line and not line.startswith('#'))
    require(settings.get('enable-rcon') == 'true' and
            int(settings.get('rcon.port', '0')) == cfg['rconPort'] and
            int(settings.get('server-port', '25565')) == cfg['minecraftPort'],
            'Настройки RCON и игрового порта Vanilla не соответствуют реальному хосту')
    password = os.environ.get('LAUNCHER_VANILLA_RCON_PASSWORD', '')
    server_log = Path(cfg['serverLog']); sidecar_log = Path(cfg['sidecarLog'])
    for log in (server_log, sidecar_log):
        require(log.is_file() and not log.is_symlink() and log.stat().st_size <= 32<<20,
                'Исходный журнал сервера отсутствует, слишком велик или является символической ссылкой')
    require(server_log.resolve() == (server_dir / 'logs/latest.log').resolve(),
            'Указанный журнал не является текущим журналом сервера Vanilla')
    before_log = server_log.read_text(errors='replace')
    require('Starting minecraft server version 1.21.1' in before_log and
            re.search(r'Done \([0-9.]+s\)!', before_log), 'Не подтверждены запуск и готовность сервера')
    sidecar_text = sidecar_log.read_text(errors='replace')
    require(f'Launcher Vanilla ServerBridge {VERSION} ready;' in sidecar_text,
            'Рабочая вспомогательная служба не прошла проверку подлинности при запуске')
    running = status('127.0.0.1', cfg['minecraftPort'], '1.21.1')
    players = rcon('127.0.0.1', cfg['rconPort'], password, 'list')
    require('players online' in players.lower(), 'RCON не вернул фактический список игроков')
    def clock():
        raw = rcon('127.0.0.1', cfg['rconPort'], password, 'time query gametime')
        match = re.search(r'\b([0-9]{1,20})\b', raw)
        require(match is not None, 'RCON не вернул число игровых тактов')
        return int(match.group(1))
    previous = clock(); sleep(2); current = clock()
    require(current > previous and current - previous < 2000, 'JVM Vanilla не продвигает игровые такты')
    inspect_process(cfg['sidecarPid'], jar, cfg['sidecarSha256'])
    return {'targetId': 'vanilla', 'coverage': 'sidecar-rcon-e2e', 'version': VERSION,
            'status': 'LIVE_VERIFIED_REVIEW_REQUIRED', 'javaPid': cfg['sidecarPid'],
            'sidecarJarSha256': cfg['sidecarSha256'], 'serverLogSha256': file_hash(server_log),
            'sidecarLogSha256': file_hash(sidecar_log), 'minecraft': running,
            'gameTicksBefore': previous, 'gameTicksAfter': current,
            'independentGA': False}

#!/usr/bin/env python3
"""Actual matching-server and gameplay observations for an immutable staged client.

Not release attestation. Never count TCP, the login line, a fabricated JSON report,
or a runner-side server command as proof of client gameplay.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import sys
import stat
import struct
import subprocess
import tempfile
import time
import zipfile

from staged_readiness_0343 import command, find_window, log_health

BOOT_VERSION = re.compile(r'(?im)Starting minecraft server version\s+([^\s]+)')
BOOT_READY = re.compile(r'(?im)\bDone \([\d.,]+s\)! For help, type ["\x27]?help')
JOIN = re.compile(r'(?im)\b([A-Za-z0-9_]{1,16})\s+(?:joined the game|logged in with entity id)')
LOADER_MARKER = {
    'fabric': re.compile(r'(?i)Fabric Loader[^\n]{0,130}'),
    'quilt': re.compile(r'(?i)Quilt Loader[^\n]{0,130}'),
    'forge': re.compile(r'(?i)(?:MinecraftForge|Forge Mod Loader|Forge version)[^\n]{0,130}'),
    'neoforge': re.compile(r'(?i)(?:NeoForge|NeoForged)[^\n]{0,130}'),
}
BRIDGE_READY = re.compile(r'(?im)NeverLauncher[^\n]{0,130}(?:Server\s*Bridge|Bridge)[^\n]{0,130}(?:ready|enabled|started)')
POSITION = re.compile(r'\[\s*(-?\d+(?:\.\d+)?)[dDfF]?,\s*(-?\d+(?:\.\d+)?)[dDfF]?,\s*(-?\d+(?:\.\d+)?)[dDfF]?\s*\]')
GAMETIME = re.compile(r'(?i)\b(?:time is|game time is)\s+(\d+)')
CRASH = re.compile(r'(?i)\b(?:Exception in server tick loop|OutOfMemoryError|A fatal error has been detected|Failed to start the minecraft server|crash report|ServerWatchdog).*')


def file_sha256(path):
    dig = hashlib.sha256()
    with open(path, 'rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            dig.update(data)
    return dig.hexdigest()


def safe_bundle_extract(bundle, directory):
    """Pinned complete server distribution, never downloaded or rebuilt by worker."""
    total = 0
    with zipfile.ZipFile(bundle) as archive:
        if len(archive.infolist()) > 50000:
            raise ValueError('server bundle has excessive entries')
        names = set()
        for item in archive.infolist():
            name = item.filename
            parts = PurePosixPath(name.rstrip('/')).parts
            mode = (item.external_attr >> 16)
            if (not name or name.startswith('/') or '\\' in name or '\x00' in name or
                    any(p in ('', '.', '..') for p in parts) or stat.S_ISLNK(mode) or
                    stat.S_IFMT(mode) not in (0, stat.S_IFDIR, stat.S_IFREG) or
                    name.rstrip('/') in names):
                raise ValueError('unsafe or duplicate server bundle path')
            names.add(name.rstrip('/'))
            total += item.file_size
            if total > 8 * 1024 * 1024 * 1024:
                raise ValueError('server bundle uncompressed size exceeds limit')
        # Canonicalized paths have been checked; extract only under new isolated root.
        for item in archive.infolist():
            target = directory.joinpath(*PurePosixPath(item.filename.rstrip('/')).parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as src, open(target, 'xb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)


def verify_matching_server(log, minecraft, loader, loader_version='', requires_bridge=False, bridge_version=''):
    """Positive boot version, loader version and plugin startup from this server log."""
    if CRASH.search(log):
        raise RuntimeError('matching server fatal/crash state')
    match = BOOT_VERSION.search(log)
    if not match or match.group(1) != minecraft:
        raise RuntimeError('server boot did not positively confirm exact Minecraft version')
    if not BOOT_READY.search(log):
        raise RuntimeError('server has not finished preparing its world')
    if loader not in ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge'):
        raise RuntimeError('unsupported staged Minecraft loader')
    if loader != 'vanilla':
        match = LOADER_MARKER[loader].search(log)
        if not match or not loader_version or not re.search(r'(?<![\d.])' + re.escape(loader_version) + r'(?![\d.])', match.group(0)):
            raise RuntimeError('server loader/version not confirmed by actual boot log')
    if requires_bridge:
        match = BRIDGE_READY.search(log)
        if not match or not bridge_version or not re.search(r'(?<![\d.])' + re.escape(bridge_version) + r'(?![\d.])', match.group(0)):
            raise RuntimeError('required ServerBridge identity/version did not report startup')
    return True


class Rcon:
    """Minecraft Source RCON, with authenticated loopback connection per query."""
    def __init__(self, port, password):
        self.port = port
        self.password = password

    @staticmethod
    def recv_exact(sock, count):
        out = bytearray()
        while len(out) < count:
            chunk = sock.recv(count - len(out))
            if not chunk:
                raise ConnectionError('RCON connection ended')
            out.extend(chunk)
        return bytes(out)

    @staticmethod
    def send(sock, number, kind, payload):
        body = struct.pack('<ii', number, kind) + payload.encode('utf-8') + b'\0\0'
        if len(body) > 4096:
            raise ValueError('RCON request too long')
        sock.sendall(struct.pack('<i', len(body)) + body)

    @classmethod
    def recv(cls, sock):
        length, = struct.unpack('<i', cls.recv_exact(sock, 4))
        if not 10 <= length <= 1024 * 1024:
            raise ValueError('invalid RCON packet length')
        body = cls.recv_exact(sock, length)
        if body[-2:] != b'\0\0':
            raise ValueError('invalid RCON packet terminator')
        req, kind = struct.unpack('<ii', body[:8])
        return req, kind, body[8:-2].decode('utf-8', 'replace')

    def query(self, command_text):
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as sock:
            sock.settimeout(3)
            self.send(sock, 5, 3, self.password)
            # Source RCON may emit a type=0 response before type=2 auth.
            for _ in range(3):
                request_id, kind, _ = self.recv(sock)
                if request_id == -1:
                    raise PermissionError('matching server RCON authentication rejected')
                if kind == 2:
                    if request_id != 5:
                        raise PermissionError('matching server RCON authentication rejected')
                    break
            else:
                raise PermissionError('matching server RCON authentication was not confirmed')
            self.send(sock, 6, 2, command_text)
            response = []
            # Some servers split long responses; evidence commands are short.
            for _ in range(4):
                request_id, _, part = self.recv(sock)
                if request_id != 6:
                    raise ValueError('RCON response identity mismatch')
                response.append(part)
                if len(part) < 3500:
                    break
            return ''.join(response)


def player_online(response, username):
    # RCON `list` response includes an enumerated player list after ':'.
    if ':' not in response or not re.search(r'(?i)\bThere are\s+\d+\s+of\b', response):
        return False
    return username in [part.strip() for part in response.split(':', 1)[1].split(',')]


def parse_position(response):
    found = POSITION.search(response)
    if not found:
        raise RuntimeError('server did not expose actual player position')
    xyz = tuple(float(value) for value in found.groups())
    if not all(math.isfinite(v) and abs(v) < 30000000 for v in xyz):
        raise RuntimeError('invalid server position values')
    return xyz


def parse_gametime(response):
    found = GAMETIME.search(response)
    if not found:
        raise RuntimeError('server did not expose advancing game ticks')
    return int(found.group(1))


def changed_position(a, b):
    return math.dist(a, b) >= 0.22


class MatchingServer:
    def __init__(self, work, java, cli, minecraft, loader, loader_version, bundle='', bundle_sha='', bridge_path='', bridge_sha='', server_entry='', bridge_version='', online_mode=False):
        self.work = Path(work)
        self.root = self.work / 'matching-server'
        self.java = str(java)
        self.cli = str(cli)
        self.minecraft = minecraft
        self.loader = loader
        self.loader_version = loader_version
        self.bundle = bundle
        self.bundle_sha = bundle_sha
        self.bridge_path = bridge_path
        self.bridge_sha = bridge_sha
        self.bridge_version = bridge_version
        self.online_mode = bool(online_mode)
        self.server_entry = server_entry
        self.process = None
        self.log_stream = None
        self.log_file = self.work / 'matching-server.log'
        self.rcon_password = secrets.token_urlsafe(32)
        self.port = self.free_port()
        self.rcon_port = self.free_port()
        while self.port == self.rcon_port:
            self.rcon_port = self.free_port()
        self.rcon = Rcon(self.rcon_port, self.rcon_password)
        self.requires_bridge = loader != 'vanilla' or bool(bridge_path)
        self.artifact_sha = ''

    @staticmethod
    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def prepare(self):
        if self.root.exists():
            raise ValueError('matching-server working root already exists')
        self.root.mkdir(mode=0o700)
        if self.bundle:
            if not re.fullmatch('[0-9a-fA-F]{64}', self.bundle_sha):
                raise ValueError('server bundle requires pinned SHA-256')
            if file_sha256(self.bundle).lower() != self.bundle_sha.lower():
                raise ValueError('server bundle differs from pinned SHA-256')
            safe_bundle_extract(self.bundle, self.root)
            self.artifact_sha = self.bundle_sha.lower()
        else:
            if self.loader != 'vanilla':
                raise RuntimeError('modded matching server requires a pinned complete server bundle')
            evidence = self.work / 'matching-server-install.json'
            proc = subprocess.run([self.cli, 'runtime', 'vanilla-server', '--minecraft', self.minecraft,
                                   '--server-dir', str(self.root), '--output', str(evidence)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300, check=False)
            if proc.returncode:
                raise RuntimeError('Mojang matching server install failed')
            installed = json.loads(evidence.read_text())
            if installed.get('status') != 'installed-and-verified' or installed.get('minecraftVersion') != self.minecraft:
                raise RuntimeError('Mojang server version or integrity not verified')
            if file_sha256(self.root / 'server.jar') != installed.get('sha256'):
                raise RuntimeError('downloaded Mojang server JAR changed after verification')
            self.artifact_sha = installed['sha256']
        entry = self.server_entry or (('run.bat' if sys.platform=='win32' else 'run.sh') if self.loader in ('forge', 'neoforge') else 'server.jar')
        if not entry or '/' in entry or '\\' in entry or entry in ('.', '..'):
            raise ValueError('server executable must be a file at bundle root')
        if not (self.root / entry).is_file() or (self.root / entry).is_symlink():
            raise RuntimeError('matching server executable missing from pinned bundle')
        self.entry = entry
        if self.requires_bridge:
            if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?', self.bridge_version):
                raise RuntimeError('required ServerBridge needs an operator-pinned version')
            path = PurePosixPath(self.bridge_path)
            if (not self.bridge_path or path.is_absolute() or '..' in path.parts or '\\' in self.bridge_path or
                    not re.fullmatch('[0-9a-fA-F]{64}', self.bridge_sha) or
                    not (self.root / self.bridge_path).is_file() or
                    file_sha256(self.root / self.bridge_path).lower() != self.bridge_sha.lower()):
                raise RuntimeError('required ServerBridge binary missing or SHA-256 mismatch')
            if path.parts[0] != ('plugins' if self.loader == 'vanilla' else 'mods'):
                raise RuntimeError('ServerBridge must be in loader plugin/mod directory')
        (self.root / 'eula.txt').write_text('eula=true\n')
        # Dedicated, ephemeral loopback-only offline integration server. This
        # does NOT certify official login, custom auth or a production Guard policy.
        props = {'server-ip':'127.0.0.1', 'server-port':str(self.port),
                 'online-mode':'true' if self.online_mode else 'false','enforce-secure-profile':'false','white-list':'false',
                 'enable-rcon':'true','rcon.port':str(self.rcon_port),
                 'rcon.password':self.rcon_password,'spawn-protection':'0',
                 'view-distance':'3','simulation-distance':'3','generate-structures':'false',
                 'level-type':'flat','gamemode':'creative','allow-flight':'true',
                 'max-players':'2','motd':'NeverLauncher isolated staged gameplay test'}
        # Do not allow an attacker-provided server.properties to override loopback.
        (self.root / 'server.properties').write_text(''.join(f'{key}={value}\n' for key,value in props.items()))
        return self

    def start(self, timeout=180):
        if sys.platform=='win32' and self.entry.endswith('.sh'):
            raise RuntimeError('Windows matching server cannot execute POSIX run.sh; use pinned run.bat')
        if sys.platform!='win32' and self.entry.endswith('.bat'):
            raise RuntimeError('POSIX matching server cannot execute Windows run.bat')
        command_line = (['cmd.exe','/d','/c',self.entry,'nogui'] if self.entry.endswith('.bat') else
                        ['bash',self.entry,'nogui'] if self.entry.endswith('.sh') else
                        [self.java, '-Xms256M', '-Xmx1536M', '-jar', self.entry, 'nogui'])
        self.log_stream = open(self.log_file, 'xb')
        from process_group_03410 import group_flags
        self.process = subprocess.Popen(command_line, cwd=self.root, stdin=subprocess.DEVNULL,
                                        stdout=self.log_stream, stderr=subprocess.STDOUT,
                                        **group_flags())
        limit = time.monotonic() + timeout
        while time.monotonic() < limit:
            if self.process.poll() is not None:
                raise RuntimeError('matching server exited before world was ready')
            log = self.log_text()
            if CRASH.search(log):
                raise RuntimeError('matching server crashed during boot')
            if BOOT_READY.search(log):
                verify_matching_server(log, self.minecraft, self.loader, self.loader_version, self.requires_bridge, self.bridge_version)
                # A reachable TCP socket alone is not startup; positively query
                # a server command after verifying complete boot & bridge.
                try:
                    if parse_gametime(self.rcon.query('time query gametime')) >= 0:
                        return self
                except (OSError, ConnectionError, ValueError, RuntimeError, PermissionError):
                    # RCON binds after the world-ready console marker on some
                    # server versions; never confuse TCP readiness with a
                    # successful authenticated command.
                    pass
            time.sleep(1)
        raise TimeoutError('matching server did not prove world/loader readiness')

    def log_text(self):
        if not self.log_file.exists():
            return ''
        with open(self.log_file, 'rb') as stream:
            stream.seek(max(0, self.log_file.stat().st_size - 2 * 1024 * 1024))
            return stream.read().decode('utf-8', 'replace')

    def close(self):
        import signal
        if self.process:
            if self.process.poll() is None:
                try:
                    from process_group_03410 import stop_tree
                    stop_tree(self.process)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    from process_group_03410 import kill_tree
                    kill_tree(self.process)
                    self.process.wait(timeout=10)
        if self.log_stream:
            self.log_stream.close()


class GameplayObserver:
    """Independent server-side RCON + PID-bound GUI action + client log evidence."""
    def __init__(self, server, client_dir, java, loader, username, output, run_id, started_at):
        self.server = server
        self.client_dir = Path(client_dir)
        self.java = java
        self.loader = loader
        self.username = username
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.started_at = started_at
        self.root_pid = 0
        self.last_probe = 0
        self.joined = False
        self.position_before = None
        self.position_after = None
        self.ticks_before = None
        self.ticks_after = None
        self.first_frame = None
        self.last_frame = None
        self.action_sent = False
        self.action_time = None
        self.failure = ''
        self.window_pid = None
        self.client_log_seen = False
        self.status = 'pending'
        self.blocked = ''

    def screenshot(self, wid, name):
        path = self.output / name
        path.unlink(missing_ok=True)
        if sys.platform in ('win32','darwin'):
            from native_window_03410 import screenshot_world
            return screenshot_world(wid,path)
        command(['scrot', '--window', wid, '--silent', str(path)], 10)
        values = command(['identify', '-format', '%w %h %[entropy]', str(path)], 7).split()
        if len(values) != 3 or int(values[0]) < 640 or int(values[1]) < 400 or float(values[2]) < .12:
            path.unlink(missing_ok=True)
            raise RuntimeError('Minecraft world frame is not sufficiently rendered')
        return file_sha256(path)

    def tick(self):
        if self.failure or time.monotonic() - self.last_probe < 1.5:
            return
        self.last_probe = time.monotonic()
        if self.server.process.poll() is not None:
            self.failure = 'matching server exited during gameplay'
            self.status = 'failed'
            return
        server_log = self.server.log_text()
        if CRASH.search(server_log):
            self.failure = 'matching server fatal state during gameplay'
            self.status = 'failed'
            return
        # A late crash cannot be hidden by a previously observed movement.
        healthy, health_detail = log_health(self.client_dir, None, self.loader)
        if health_detail.startswith(('fatal','crash')):
            self.failure = health_detail
            self.status = 'failed'
            return
        if self.status == 'passed':
            return
        try:
            verify_matching_server(server_log, self.server.minecraft, self.loader,
                                   self.server.loader_version, self.server.requires_bridge, self.server.bridge_version)
            self.client_log_seen = any(p.stat().st_mtime >= self.started_at - 1 and
                ('Connecting to' in p.read_text(encoding='utf-8', errors='replace')[-100000:] or
                 'Joining world' in p.read_text(encoding='utf-8', errors='replace')[-100000:] or
                 'Connecting to server' in p.read_text(encoding='utf-8', errors='replace')[-100000:])
                for p in (self.client_dir / 'logs').glob('*.log') if p.is_file())
            if not self.client_log_seen:
                return
            if not any(user == self.username for user in JOIN.findall(server_log)):
                return
            if not player_online(self.server.rcon.query('list'), self.username):
                return
            self.joined = True
            window = find_window(self.root_pid, self.java)
            if not window:
                return
            wid, pid = window
            self.window_pid = pid
            if not self.action_sent:
                self.position_before = parse_position(self.server.rcon.query(f'data get entity {self.username} Pos'))
                self.ticks_before = parse_gametime(self.server.rcon.query('time query gametime'))
                self.first_frame = self.screenshot(wid, 'world-before.png')
                if sys.platform in ('win32','darwin'):
                    from native_window_03410 import move_forward
                    move_forward(wid,2)
                else:
                    command(['xdotool', 'windowfocus', '--sync', wid], 5)
                    # Actual window input, never server-side teleport.
                    command(['xdotool', 'keydown', '--clearmodifiers', 'w'], 5)
                    try:
                        time.sleep(2)
                    finally:
                        command(['xdotool', 'keyup', 'w'], 5)
                self.action_time = time.monotonic()
                self.action_sent = True
                return
            if time.monotonic() - self.action_time < 1:
                return
            self.position_after = parse_position(self.server.rcon.query(f'data get entity {self.username} Pos'))
            self.ticks_after = parse_gametime(self.server.rcon.query('time query gametime'))
            self.last_frame = self.screenshot(wid, 'world-after.png')
            if self.ticks_after <= self.ticks_before:
                self.failure = 'matching server game ticks did not advance'
            elif not changed_position(self.position_before, self.position_after):
                self.failure = 'actual client keyboard action did not move server-side player'
            elif self.first_frame == self.last_frame:
                self.failure = 'world rendering did not change after client action'
            else:
                self.status = 'passed'
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, ConnectionError) as exc:
            from native_window_03410 import GUIUnavailable
            if isinstance(exc,GUIUnavailable):
                self.blocked=str(exc)[:240]
                self.status='blocked'
                return
            # A missing positive signal is not PASS; retry short-lived RCON/GUI
            # contention, but retain why a completed attempt was inconclusive.
            self.last_error = str(exc)[:240]

    def evidence(self):
        return {'schemaVersion':'neverlauncher.staged-gameplay.v1','runId':self.run_id,
                'serverArtifactSha256':self.server.artifact_sha,
                'minecraftVersion':self.server.minecraft,'loader':self.loader,
                'loaderVersion':self.server.loader_version,'serverBridgeVersion':self.server.bridge_version,'serverPort':self.server.port,
                'serverProcessId':self.server.process.pid if self.server.process else None,
                'windowJavaProcessId':self.window_pid,'clientConnectionLogObserved':self.client_log_seen,
                'serverJoinAndOnline':self.joined,'clientInputSent':self.action_sent,
                'ticksBefore':self.ticks_before,'ticksAfter':self.ticks_after,
                'positionBefore':self.position_before,'positionAfter':self.position_after,
                'frameBeforeSha256':self.first_frame,'frameAfterSha256':self.last_frame,
                'status':self.status,'blocked':self.blocked,
                'failure':self.failure or getattr(self,'last_error','')}

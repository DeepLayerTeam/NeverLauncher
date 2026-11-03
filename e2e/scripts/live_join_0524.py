#!/usr/bin/env python3
"""Real version-matched Minecraft multiplayer compatibility observation.

An ephemeral, localhost-bound dedicated server is started from a verified Mojang
server JAR, or an independently SHA-256 pinned loader server distribution. No
client process / timeout alone can satisfy this gate. The server-side RCON and
console join observations are taken while the game client is actually online.
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
PLAYER = 'NL_Cert_Client'  # Actual username in Runtime's compatibility launcher.


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
        require(k not in out, 'duplicate JSON key: ' + k)
        out[k] = v
    return out


def atomically_write(path, payload):
    path = Path(path)
    contents = (json.dumps(payload, sort_keys=True, indent=2) + '\n').encode()
    # Refuse replacing a malicious preexisting receipt or following symlinks.
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
    require(manifest.get('schema') == 'neverlauncher.compatibility-server/0.52.4', 'server pin schema mismatch')
    targets = manifest.get('targets')
    require(type(targets) is dict, 'server pin targets missing')
    entry = targets.get(args.target)
    require(type(entry) is dict, 'target has no approved dedicated server distribution: ' + args.target)
    require(all(entry.get(k) == getattr(args, attribute) for k, attribute in
                (('loader', 'loader'), ('minecraft', 'minecraft'))), 'server bundle target version/loader mismatch')
    # Pinned loader version is the *resolved* installed client loader, not 'latest'.
    require(entry.get('loaderVersion', '') == args.loader_version, 'server bundle loader version mismatch')
    sha = entry.get('sha256')
    require(type(sha) is str and SHA.fullmatch(sha), 'bundle SHA-256 pin invalid')
    name = entry.get('file')
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip', name) and '..' not in name,
            'bundle path must be a simple pinned ZIP basename')
    require(bool(args.bundle_dir), 'server bundle directory is required')
    directory = Path(args.bundle_dir).resolve(strict=True)
    path = directory / name
    require(path.is_file() and not path.is_symlink() and path.resolve().parent == directory,
            'pinned server bundle is missing or unsafe')
    require(path.stat().st_size <= 3 * 1024 * 1024 * 1024, 'server bundle exceeds size limit')
    require(file_sha256(path) == sha, 'dedicated server ZIP does not match pinned SHA-256')
    server_entry = entry.get('serverEntry', '')
    require(type(server_entry) is str and (not server_entry or re.fullmatch(r'[a-zA-Z0-9._-]{1,80}', server_entry)),
            'invalid pinned server entry')
    return str(path), sha, server_entry, file_sha256(Path(args.pins))


def serve(args):
    require(ID.fullmatch(args.target) is not None, 'invalid target ID')
    require(args.loader in ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge'), 'unknown loader')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,63}', args.minecraft) is not None, 'invalid Minecraft version')
    runtime = Path(args.runtime).resolve(strict=True)
    require(runtime.is_dir() and not runtime.is_symlink(), 'unsafe runtime directory')
    for name in ('live-server-ready.json', 'live-server-witness.json', 'live-server-stopped.json', 'live-server-stop.request', 'live-join.json'):
        require(not (runtime / name).exists(), 'stale live-join evidence: ' + name)
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
        # Observe the server and RCON while the real JVM client is still present.
        # A later client timeout cannot manufacture this contemporaneous evidence.
        started = time.monotonic()
        while running and time.monotonic() - started < args.monitor_seconds:
            if (runtime / 'live-server-stop.request').exists():
                normal_stop = True
                break
            if server.process.poll() is not None:
                raise RuntimeError('live dedicated Minecraft server exited')
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
                            # Keep server running for independent verification, then
                            # shut down gracefully when shell's cleanup trap fires.
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
                raise RuntimeError('real Minecraft join was not observed before deadline')
    finally:
        # A successful witness is not sufficient if the dedicated game JVM died
        # before the caller finished the client run. Seal only an orderly stop.
        healthy_at_stop = (normal_stop and server.process is not None
                           and server.process.poll() is None
                           and (runtime / 'live-server-witness.json').is_file())
        if healthy_at_stop:
            # Ask the *actual* server JVM to save and stop through authenticated
            # RCON; a killed process or a crashing server must never get PASS.
            try:
                server.rcon.query('stop')
            except (OSError, ValueError, RuntimeError, PermissionError, ConnectionError):
                pass  # RCON socket may close as the server obeys stop.
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
    require(normal_stop, 'live server did not receive orderly stop request')
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
    require(ready.get('schema') == 'neverlauncher.compatibility-server-ready/0.52.4', 'ready schema mismatch')
    require(witness.get('schema') == 'neverlauncher.compatibility-join-witness/0.52.4', 'witness schema mismatch')
    for label, doc in (('ready', ready), ('witness', witness), ('stopped', stopped)):
        require(all(doc.get(k) == v for k, v in run_binding().items()),
                label + ': original CI commit/run/attempt evidence was replayed')
    for label, doc in (('ready', ready), ('witness', witness)):
        require(doc.get('targetId') == args.target and doc.get('minecraftVersion') == args.minecraft and
                doc.get('loader') == args.loader and doc.get('loaderVersion') == args.loader_version,
                label + ': client/server identity mismatch')
    for field in ('serverPid', 'port', 'serverArtifactSha256'):
        require(ready.get(field) == witness.get(field), 'witness server identity changed: ' + field)
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
            'server did not remain alive until orderly shutdown or console log changed')
    require(not CRASH.search(log), 'dedicated game server crashed during the run')
    require(PLAYER in JOIN.findall(log) and witness.get('username') == PLAYER and
            witness.get('joinedFromServerLog') is True and witness.get('playerOnlineViaRcon') is True,
            'server console/RCON did not corroborate real client join')
    require(type(witness.get('tickBefore')) is int and type(witness.get('tickAfter')) is int and
            witness['tickAfter'] > witness['tickBefore'], 'live Minecraft world did not advance')
    require(cert.get('status') == 'passed' and cert.get('matchingServer') == '127.0.0.1' and
            cert.get('matchingServerPort') == ready.get('port') and
            (cert.get('success') is True or cert.get('timedOut') is True),
            'verified client did not target the actual dedicated server')
    require(args.profile == cert.get('minecraftVersion'), 'client profile not the installed loader profile')
    require(cert.get('requiredJavaMajor') == args.java_major and
            cert.get('detectedJavaMajor') == args.java_major and
            type(cert.get('classpathEntries')) is int and cert['classpathEntries'] > 0,
            'JVM/loader run was not verified')
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
